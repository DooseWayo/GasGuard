/**
 * Load and fault tests for SBOM ingestion.
 *
 * These run in the normal jest suite with fixed seeds, so failures are
 * reproducible. They check that work is never lost or duplicated under
 * concurrency and injected faults, and that memory held by the queue stays
 * within the configured bounds.
 */

import { SbomIngestionConfig } from "./sbom-config";
import {
  SbomIngestionService,
  SbomProcessOutcome,
} from "./sbom-ingestion.service";
import { SbomLogger } from "./sbom-metrics";
import {
  InMemorySbomStore,
  SbomStore,
  SbomStoreWriteResult,
  StoredSbom,
} from "./sbom-store";

const silentLogger: SbomLogger = { log: () => undefined };

/** Deterministic PRNG (mulberry32) so fault patterns are reproducible. */
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Store that yields between operations, fails a fraction of writes, and
 * "crashes" a fraction of workers by never resolving their write, the way a
 * worker process that dies mid-job never reports back.
 */
class ChaosStore implements SbomStore {
  readonly inner = new InMemorySbomStore();
  writes = 0;
  hung = 0;
  failed = 0;
  constructor(
    private readonly random: () => number,
    private readonly failRate: number,
    private readonly hangRate: number,
  ) {}

  async put(record: StoredSbom): Promise<SbomStoreWriteResult> {
    await new Promise((resolve) => setImmediate(resolve));
    const roll = this.random();
    if (roll < this.hangRate) {
      this.hung++;
      return new Promise<SbomStoreWriteResult>(() => undefined);
    }
    if (roll < this.hangRate + this.failRate) {
      this.failed++;
      throw new Error("injected storage fault");
    }
    this.writes++;
    return this.inner.put(record);
  }
  get(tenantId: string, repositoryId: string, scanId: string) {
    return this.inner.get(tenantId, repositoryId, scanId);
  }
  delete(tenantId: string, repositoryId: string, scanId: string) {
    return this.inner.delete(tenantId, repositoryId, scanId);
  }
}

function sbomFor(index: number, components: number): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: Array.from({ length: components }, (_, c) => ({
      name: `pkg-${index}-${c}`,
      version: "1.0.0",
      purl: `pkg:npm/pkg-${index}-${c}@1.0.0`,
    })),
  });
}

function build(store: SbomStore, config: Partial<SbomIngestionConfig>) {
  const clock = { now: 0 };
  const service = new SbomIngestionService({
    store,
    logger: silentLogger,
    clock: () => clock.now,
    config,
  });
  return { service, clock };
}

/**
 * Run `workers` concurrent polling loops. Each poll is fire-and-forget so a
 * hung write only stalls that one attempt, as a crashed worker would; the
 * clock advances between rounds so leases expire and backoffs elapse.
 */
async function runWorkers(
  service: SbomIngestionService,
  clock: { now: number },
  workers: number,
  done: () => boolean,
  tickMs: number,
  maxRounds = 10_000,
): Promise<SbomProcessOutcome[]> {
  const outcomes: SbomProcessOutcome[] = [];
  for (let round = 0; round < maxRounds && !done(); round++) {
    const polls = Array.from({ length: workers }, (_, w) =>
      service
        .processNext(`worker-${w}`)
        .then((outcome) => outcomes.push(outcome)),
    );
    // Wait for the polls that can settle; hung ones are abandoned.
    await Promise.race([
      Promise.allSettled(polls),
      new Promise((r) => setTimeout(r, 5)),
    ]);
    clock.now += tickMs;
  }
  return outcomes;
}

describe("SBOM ingestion - load", () => {
  it("ingests 400 SBOMs across 10 tenants with 8 workers, each exactly once", async () => {
    const store = new InMemorySbomStore();
    const { service, clock } = build(store, {
      maxPendingJobs: 400,
      maxPendingJobsPerTenant: 40,
    });
    const jobIds = new Set<string>();
    for (let i = 0; i < 400; i++) {
      const result = await service.submit({
        tenantId: `tenant-${i % 10}`,
        repositoryId: "org/repo",
        scanId: `scan-${i}`,
        document: sbomFor(i, 5),
      });
      jobIds.add(result.jobId);
    }

    const outcomes = await runWorkers(
      service,
      clock,
      8,
      () => service.queueStats().completed === 400,
      10,
    );
    const completed = outcomes
      .filter((o) => o.status === "completed")
      .map((o) => (o as { jobId: string }).jobId);

    expect(completed).toHaveLength(400);
    expect(new Set(completed)).toEqual(jobIds);
    expect(outcomes.some((o) => o.status === "stale")).toBe(false);
    expect(store.size()).toBe(400);
    expect(service.metrics.snapshot()).toMatchObject({
      jobsCompleted: 400,
      componentsIngested: 2_000,
    });
  });

  it("bounds in-flight jobs and sheds load with QUEUE_FULL", async () => {
    const { service, clock } = build(new InMemorySbomStore(), {
      maxPendingJobs: 50,
      maxPendingJobsPerTenant: 50,
      finishedJobRetentionMs: 1_000,
    });

    let accepted = 0;
    let shed = 0;
    for (let i = 0; i < 200; i++) {
      try {
        await service.submit({
          tenantId: "t",
          repositoryId: "r",
          scanId: `s-${i}`,
          document: sbomFor(i, 1),
        });
        accepted++;
      } catch (error) {
        expect(error).toMatchObject({ code: "QUEUE_FULL", retryable: true });
        shed++;
      }
      expect(service.queueSize()).toBeLessThanOrEqual(50);
    }
    expect({ accepted, shed }).toEqual({ accepted: 50, shed: 150 });

    await service.drain("worker-1");
    expect(service.queueStats()).toMatchObject({
      pending: 0,
      running: 0,
      completed: 50,
    });

    // Finished records age out, so memory returns to zero once the window passes.
    clock.now += 1_000;
    expect(await service.processNext("worker-1")).toEqual({ status: "idle" });
    expect(service.queueSize()).toBe(0);
  });

  it("parses the maximum component count within a bounded time", async () => {
    const maxComponents = 50_000;
    const { service } = build(new InMemorySbomStore(), { maxComponents });
    await service.submit({
      tenantId: "t",
      repositoryId: "r",
      scanId: "big",
      document: sbomFor(0, maxComponents),
    });

    const started = Date.now();
    expect(await service.processNext("worker-1")).toMatchObject({
      status: "completed",
      components: maxComponents,
    });
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("stops work on an over-limit document at the component limit", async () => {
    const { service } = build(new InMemorySbomStore(), {
      maxComponents: 1_000,
    });
    await service.submit({
      tenantId: "t",
      repositoryId: "r",
      scanId: "huge",
      document: sbomFor(0, 20_000),
    });
    expect(await service.processNext("worker-1")).toMatchObject({
      status: "dead_lettered",
      code: "TOO_MANY_COMPONENTS",
    });
  });
});

describe("SBOM ingestion - faults", () => {
  it.each([1, 2, 3])(
    "completes every job despite storage faults and crashed workers (seed %i)",
    async (seed) => {
      const store = new ChaosStore(prng(seed), 0.2, 0.1);
      const { service, clock } = build(store, {
        maxAttempts: 25,
        leaseTtlMs: 100,
        retryBackoffMs: 10,
        maxRetryBackoffMs: 50,
        maxPendingJobs: 100,
        maxPendingJobsPerTenant: 100,
      });
      const jobs: { jobId: string; scanId: string }[] = [];
      for (let i = 0; i < 60; i++) {
        const { jobId } = await service.submit({
          tenantId: `tenant-${i % 3}`,
          repositoryId: "org/repo",
          scanId: `scan-${i}`,
          document: sbomFor(i, 3),
        });
        jobs.push({ jobId, scanId: `scan-${i}` });
      }

      const outcomes = await runWorkers(
        service,
        clock,
        6,
        () => service.queueStats().completed === 60,
        25,
      );

      // Faults actually happened, and the system recovered from all of them.
      expect(store.failed).toBeGreaterThan(0);
      expect(store.hung).toBeGreaterThan(0);
      expect(service.queueStats()).toEqual({
        pending: 0,
        running: 0,
        completed: 60,
        deadLettered: 0,
      });

      // Each job reached `completed` through exactly one successful completion.
      const completions = outcomes
        .filter((o) => o.status === "completed")
        .map((o) => (o as { jobId: string }).jobId);
      expect(completions.sort()).toEqual(jobs.map((j) => j.jobId).sort());

      // Every scan has its own, correct result, scoped to its tenant.
      for (let i = 0; i < jobs.length; i++) {
        const stored = await service.getResult(
          `tenant-${i % 3}`,
          "org/repo",
          jobs[i].scanId,
        );
        expect(stored?.jobId).toBe(jobs[i].jobId);
        expect(stored?.sbom.components[0].name).toBe(`pkg-${i}-0`);
      }

      const metrics = service.metrics.snapshot();
      expect(metrics.jobsRetried).toBe(store.failed);
      expect(metrics.leasesRecovered).toBe(store.hung);
    },
    30_000,
  );

  it("dead-letters rather than looping when a document always crashes its worker", async () => {
    const store = new ChaosStore(() => 0, 0, 1); // every write hangs
    const { service, clock } = build(store, {
      maxAttempts: 3,
      leaseTtlMs: 100,
      retryBackoffMs: 10,
    });
    const { jobId } = await service.submit({
      tenantId: "t",
      repositoryId: "r",
      scanId: "s",
      document: sbomFor(0, 1),
    });

    await runWorkers(
      service,
      clock,
      2,
      () => service.queueStats().deadLettered === 1,
      50,
      200,
    );

    expect(service.getJob("t", jobId)).toMatchObject({
      status: "dead_lettered",
      attempts: 3,
      lastErrorCode: "LEASE_EXPIRED",
    });
    expect(store.hung).toBe(3);
  });
});
