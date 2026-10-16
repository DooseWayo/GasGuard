/**
 * Integration tests across the SBOM ingestion boundaries: API-facing service,
 * job queue and leases, parser, and the durable file store.
 */

import { promises as fs, readFileSync } from "fs";
import * as os from "os";
import * as path from "path";
import { SbomIngestionConfig } from "./sbom-config";
import { SbomIngestionService } from "./sbom-ingestion.service";
import { SbomLogFields, SbomLogLevel, SbomLogger } from "./sbom-metrics";
import { parseSbom } from "./sbom-parser";
import {
  FileSbomStore,
  InMemorySbomStore,
  SbomStore,
  SbomStoreWriteResult,
  StoredSbom,
} from "./sbom-store";
import { SbomIngestionWorker } from "./sbom-worker";

const fixture = (name: string) =>
  readFileSync(path.join(__dirname, "__fixtures__", name), "utf8");
const CYCLONEDX = fixture("cyclonedx-1.5.json");
const SPDX = fixture("spdx-2.3.json");

interface LogEntry {
  level: SbomLogLevel;
  event: string;
  fields: SbomLogFields;
}

class CapturingLogger implements SbomLogger {
  readonly entries: LogEntry[] = [];
  log(level: SbomLogLevel, event: string, fields: SbomLogFields): void {
    this.entries.push({ level, event, fields });
  }
  events(): string[] {
    return this.entries.map((e) => e.event);
  }
}

/** Store wrapper whose `put` can be made to fail or block on demand. */
class ControllableStore implements SbomStore {
  failuresRemaining = 0;
  private nextGate?: Promise<void>;
  constructor(private readonly inner: SbomStore) {}

  /** Block the next `put` (only that one) until the returned function is called. */
  holdNextWrite(): () => void {
    let release!: () => void;
    this.nextGate = new Promise((resolve) => (release = resolve));
    return release;
  }

  async put(record: StoredSbom): Promise<SbomStoreWriteResult> {
    const gate = this.nextGate;
    this.nextGate = undefined;
    if (gate) {
      await gate;
    }
    if (this.failuresRemaining > 0) {
      this.failuresRemaining--;
      throw new Error("disk full: /var/lib/gasguard (password=hunter2)");
    }
    return this.inner.put(record);
  }
  get(tenantId: string, repositoryId: string, scanId: string) {
    return this.inner.get(tenantId, repositoryId, scanId);
  }
  delete(tenantId: string, repositoryId: string, scanId: string) {
    return this.inner.delete(tenantId, repositoryId, scanId);
  }
}

const tempDirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "gasguard-sbom-int-"));
  tempDirs.push(dir);
  return dir;
}
afterAll(async () => {
  await Promise.all(
    tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

function build(store: SbomStore, config: Partial<SbomIngestionConfig> = {}) {
  const clock = { now: 10_000 };
  const logger = new CapturingLogger();
  const service = new SbomIngestionService({
    store,
    logger,
    clock: () => clock.now,
    config: {
      maxRejectedRatio: 0.25,
      leaseTtlMs: 5_000,
      retryBackoffMs: 100,
      maxRetryBackoffMs: 1_000,
      maxAttempts: 3,
      ...config,
    },
  });
  return { service, clock, logger };
}

const request = (overrides: Record<string, unknown> = {}) => ({
  tenantId: "tenant-a",
  repositoryId: "org/repo",
  scanId: "scan-1",
  document: CYCLONEDX,
  ...overrides,
});

describe("SBOM ingestion - end to end with durable storage", () => {
  it.each([
    ["CycloneDX", CYCLONEDX, "cyclonedx"],
    ["SPDX", SPDX, "spdx"],
  ])(
    "ingests a %s SBOM and exposes the normalized result",
    async (_label, document, format) => {
      const { service } = build(new FileSbomStore(await tempDir()));

      const submitted = await service.submit(request({ document }));
      expect(submitted).toMatchObject({
        status: "accepted",
        jobStatus: "pending",
      });

      const outcome = await service.processNext("worker-1");
      expect(outcome).toMatchObject({
        status: "completed",
        jobId: submitted.jobId,
        superseded: false,
      });

      const stored = await service.getResult("tenant-a", "org/repo", "scan-1");
      expect(stored?.sbom.format).toBe(format);
      expect(stored?.sbom).toEqual(parseSbom(document, service.config));
      expect(service.getJob("tenant-a", submitted.jobId)?.status).toBe(
        "completed",
      );
    },
  );

  it("keeps results available after a restart", async () => {
    const dir = await tempDir();
    const first = build(new FileSbomStore(dir));
    await first.service.submit(request());
    await first.service.drain("worker-1");

    const restarted = build(new FileSbomStore(dir));
    const stored = await restarted.service.getResult(
      "tenant-a",
      "org/repo",
      "scan-1",
    );
    expect(stored?.sbom.stats.accepted).toBe(4);
  });

  it("returns the existing job for an identical resubmission", async () => {
    const { service } = build(new InMemorySbomStore());
    const first = await service.submit(request());
    const again = await service.submit(
      request({ document: Buffer.from(CYCLONEDX) }),
    );
    expect(again).toMatchObject({ status: "duplicate", jobId: first.jobId });
    expect(await service.drain("worker-1")).toHaveLength(1);
  });
});

describe("SBOM ingestion - tenant isolation", () => {
  it("scopes jobs and results to the submitting tenant", async () => {
    const { service } = build(new FileSbomStore(await tempDir()));
    const a = await service.submit(request({ tenantId: "tenant-a" }));
    const b = await service.submit(
      request({ tenantId: "tenant-b", document: SPDX }),
    );
    await service.drain("worker-1");

    expect(service.getJob("tenant-b", a.jobId)).toBeUndefined();
    expect(service.getJob("tenant-a", b.jobId)).toBeUndefined();
    expect(
      (await service.getResult("tenant-a", "org/repo", "scan-1"))?.sbom.format,
    ).toBe("cyclonedx");
    expect(
      (await service.getResult("tenant-b", "org/repo", "scan-1"))?.sbom.format,
    ).toBe("spdx");
    expect(
      await service.getResult("tenant-c", "org/repo", "scan-1"),
    ).toBeUndefined();
  });
});

describe("SBOM ingestion - submission validation", () => {
  it.each([
    ["missing tenant", { tenantId: "" }, "INVALID_REQUEST"],
    ["whitespace in scan id", { scanId: "scan 1" }, "INVALID_REQUEST"],
    [
      "path-like repository id with leading dot",
      { repositoryId: "../repo" },
      "INVALID_REQUEST",
    ],
    [
      "non-string document",
      { document: { bomFormat: "CycloneDX" } },
      "INVALID_REQUEST",
    ],
    ["empty document", { document: "" }, "INVALID_REQUEST"],
  ])("rejects %s", async (_label, overrides, code) => {
    const { service } = build(new InMemorySbomStore());
    await expect(
      service.submit(request(overrides) as never),
    ).rejects.toMatchObject({ code });
    expect(service.metrics.snapshot().submissionRejections).toEqual({
      [code]: 1,
    });
  });

  it("rejects oversized documents before queueing them", async () => {
    const { service } = build(new InMemorySbomStore(), {
      maxDocumentBytes: 100,
    });
    await expect(service.submit(request())).rejects.toMatchObject({
      code: "DOCUMENT_TOO_LARGE",
    });
    expect(service.queueSize()).toBe(0);
  });

  it("refuses submissions when disabled", async () => {
    const { service } = build(new InMemorySbomStore(), { enabled: false });
    await expect(service.submit(request())).rejects.toMatchObject({
      code: "INGESTION_DISABLED",
      retryable: false,
    });
  });

  it("reports QUEUE_FULL as retryable", async () => {
    const { service } = build(new InMemorySbomStore(), {
      maxPendingJobs: 1,
      maxPendingJobsPerTenant: 1,
    });
    await service.submit(request());
    await expect(
      service.submit(request({ scanId: "scan-2" })),
    ).rejects.toMatchObject({
      code: "QUEUE_FULL",
      retryable: true,
    });
  });

  it("rejects different content for a scan that is still in flight", async () => {
    const { service } = build(new InMemorySbomStore());
    await service.submit(request());
    await expect(
      service.submit(request({ document: SPDX })),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });
});

describe("SBOM ingestion - failure semantics", () => {
  it("dead-letters unsupported formats without retrying or storing anything", async () => {
    const { service, logger } = build(new InMemorySbomStore());
    const { jobId } = await service.submit(request({ document: "<bom/>" }));

    expect(await service.processNext("worker-1")).toEqual({
      status: "dead_lettered",
      jobId,
      code: "UNSUPPORTED_FORMAT",
    });
    expect(service.getJob("tenant-a", jobId)).toMatchObject({
      attempts: 1,
      lastErrorCode: "UNSUPPORTED_FORMAT",
    });
    expect(
      await service.getResult("tenant-a", "org/repo", "scan-1"),
    ).toBeUndefined();
    expect(
      logger.entries.find((e) => e.event === "sbom.ingest_failed")?.level,
    ).toBe("error");
  });

  it("retries a transient storage failure after backoff and then succeeds", async () => {
    const store = new ControllableStore(new InMemorySbomStore());
    const { service, clock } = build(store);
    store.failuresRemaining = 1;
    const { jobId } = await service.submit(request());

    expect(await service.processNext("worker-1")).toMatchObject({
      status: "retry_scheduled",
      code: "STORAGE_FAILURE",
    });
    expect(await service.processNext("worker-1")).toEqual({ status: "idle" }); // still backing off
    clock.now += 100;
    expect(await service.processNext("worker-2")).toMatchObject({
      status: "completed",
      jobId,
    });
    expect(service.metrics.snapshot()).toMatchObject({
      jobsRetried: 1,
      jobsCompleted: 1,
    });
  });

  it("dead-letters after maxAttempts persistent storage failures", async () => {
    const store = new ControllableStore(new InMemorySbomStore());
    const { service, clock } = build(store, { maxAttempts: 2 });
    store.failuresRemaining = Number.POSITIVE_INFINITY;
    const { jobId } = await service.submit(request());

    await service.processNext("worker-1");
    clock.now += 100;
    expect(await service.processNext("worker-1")).toMatchObject({
      status: "dead_lettered",
      code: "STORAGE_FAILURE",
    });
    expect(service.getJob("tenant-a", jobId)?.attempts).toBe(2);
  });

  it("accepts a new SBOM for a scan whose previous job dead-lettered", async () => {
    const { service } = build(new InMemorySbomStore());
    await service.submit(request({ document: "not json" }));
    await service.drain("worker-1");
    expect((await service.submit(request())).status).toBe("accepted");
    expect(await service.processNext("worker-1")).toMatchObject({
      status: "completed",
    });
  });
});

describe("SBOM ingestion - concurrent workers and interrupted jobs", () => {
  it("fences out a worker whose lease expired mid-write", async () => {
    const store = new ControllableStore(new InMemorySbomStore());
    const { service, clock } = build(store);
    const { jobId } = await service.submit(request());

    const release = store.holdNextWrite();
    const stalled = service.processNext("worker-1"); // blocks inside store.put
    await flush();

    clock.now += 5_000; // lease expires while worker-1 is stuck
    release();
    expect(await stalled).toEqual({ status: "stale", jobId });

    // The next poll recovers the job; it becomes claimable after backoff.
    expect(await service.processNext("worker-2")).toEqual({ status: "idle" });
    clock.now += 100;
    expect(await service.processNext("worker-2")).toMatchObject({
      status: "completed",
      jobId,
    });
    expect(service.metrics.snapshot()).toMatchObject({
      staleCompletions: 1,
      leasesRecovered: 1,
      jobsCompleted: 1,
    });
    expect(service.getJob("tenant-a", jobId)?.attempts).toBe(2);
  });

  it("never lets a late writer overwrite a newer submission's result", async () => {
    const store = new ControllableStore(new InMemorySbomStore());
    const { service, clock } = build(store);
    const old = await service.submit(request({ document: CYCLONEDX }));

    const release = store.holdNextWrite();
    const stalled = service.processNext("worker-1"); // stuck writing revision 1
    await flush();

    // worker-2 recovers and completes the old job, then a newer SBOM lands.
    clock.now += 5_000;
    expect(await service.processNext("worker-2")).toEqual({ status: "idle" });
    clock.now += 100;
    expect(await service.processNext("worker-2")).toMatchObject({
      status: "completed",
      jobId: old.jobId,
    });
    const newer = await service.submit(request({ document: SPDX }));
    expect(await service.processNext("worker-2")).toMatchObject({
      status: "completed",
      jobId: newer.jobId,
    });

    release();
    expect(await stalled).toEqual({ status: "stale", jobId: old.jobId });
    const stored = await service.getResult("tenant-a", "org/repo", "scan-1");
    expect(stored).toMatchObject({ jobId: newer.jobId });
    expect(stored?.sbom.format).toBe("spdx");
  });

  it("gives every job to exactly one worker when many race", async () => {
    const { service } = build(new FileSbomStore(await tempDir()));
    for (let i = 0; i < 20; i++) {
      await service.submit(request({ scanId: `scan-${i}` }));
    }
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, w) => service.drain(`worker-${w}`)),
    );
    const completed = results.flat().filter((o) => o.status === "completed");
    const ids = completed.map((o) => (o as { jobId: string }).jobId);
    expect(ids).toHaveLength(20);
    expect(new Set(ids).size).toBe(20);
    expect(service.queueStats()).toMatchObject({
      pending: 0,
      running: 0,
      completed: 20,
    });
  });
});

describe("SBOM ingestion - observability", () => {
  it("never logs document content, secrets, or raw error messages", async () => {
    const store = new ControllableStore(new InMemorySbomStore());
    const { service, clock, logger } = build(store);
    // Assembled at runtime so secret scanners do not flag the test itself.
    const secret = ["ghp", "_", "FAKE".repeat(9)].join("");

    await service.submit(
      request({ scanId: "bad-json", document: `{"token": ${secret}` }),
    );
    await service.submit(
      request({
        scanId: "with-secret",
        document: CYCLONEDX.replace("lodash", secret),
      }),
    );
    store.failuresRemaining = 1;
    await service.drain("worker-1");
    clock.now += 1_000;
    await service.drain("worker-1");

    const logged = JSON.stringify(logger.entries);
    expect(logged).not.toContain(secret);
    expect(logged).not.toContain("hunter2");
    expect(logged).not.toContain("disk full");
    expect(logged).not.toContain("bomFormat");
    expect(logger.events()).toEqual(
      expect.arrayContaining([
        "sbom.submitted",
        "sbom.ingest_failed",
        "sbom.ingested",
      ]),
    );
  });

  it("logs actionable fields on success and failure", async () => {
    const { service, logger } = build(new InMemorySbomStore());
    const { jobId } = await service.submit(request());
    await service.processNext("worker-1");

    const ingested = logger.entries.find((e) => e.event === "sbom.ingested");
    expect(ingested?.fields).toMatchObject({
      tenantId: "tenant-a",
      scanId: "scan-1",
      jobId,
      workerId: "worker-1",
      attempt: 1,
      format: "cyclonedx",
      components: 4,
      rejectedComponents: 1,
    });
    expect(String(ingested?.fields.contentHash)).toHaveLength(12);
  });

  it("does not echo malformed identifiers into logs", async () => {
    const { service, logger } = build(new InMemorySbomStore());
    await expect(
      service.submit(request({ scanId: "x\ninjected log line" })),
    ).rejects.toThrow();
    expect(logger.entries[0].fields.scanId).toBeUndefined();
  });

  it("keeps tenant data out of metric labels", async () => {
    const { service } = build(new InMemorySbomStore());
    await service.submit(request({ tenantId: "acme-secret-tenant" }));
    await service.drain("worker-1");
    const text = service.metricsText();
    expect(text).toContain('gasguard_sbom_queue_jobs{status="completed"} 1');
    expect(text).not.toContain("acme");
  });
});

describe("SbomIngestionWorker", () => {
  it("processes queued jobs and stops cleanly", async () => {
    const { service } = build(new InMemorySbomStore());
    await service.submit(request({ scanId: "a" }));
    await service.submit(request({ scanId: "b" }));
    const worker = new SbomIngestionWorker(service, {
      workerId: "loop-1",
      idleDelayMs: 5,
    });

    worker.start();
    await waitFor(() => service.queueStats().completed === 2);
    await worker.stop();
    expect(worker.isRunning()).toBe(false);
    expect(await service.getResult("tenant-a", "org/repo", "b")).toBeDefined();
  });

  it("validates its options", () => {
    const { service } = build(new InMemorySbomStore());
    expect(() => new SbomIngestionWorker(service, { workerId: "" })).toThrow(
      TypeError,
    );
    expect(
      () => new SbomIngestionWorker(service, { workerId: "w", idleDelayMs: 0 }),
    ).toThrow(RangeError);
  });
});

function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

async function waitFor(
  condition: () => boolean,
  timeoutMs = 2_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
