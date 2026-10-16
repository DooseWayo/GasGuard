import {
  DEFAULT_SBOM_INGESTION_CONFIG,
  SbomIngestionConfig,
} from "./sbom-config";
import { SbomJobQueue, SbomJobSubmission } from "./sbom-job-queue";
import { SbomErrorCode, SbomIngestionError } from "./sbom-types";

function setup(overrides: Partial<SbomIngestionConfig> = {}) {
  const clock = { now: 1_000 };
  const queue = new SbomJobQueue(
    {
      ...DEFAULT_SBOM_INGESTION_CONFIG,
      leaseTtlMs: 5_000,
      retryBackoffMs: 100,
      maxRetryBackoffMs: 1_000,
      maxAttempts: 3,
      finishedJobRetentionMs: 10_000,
      ...overrides,
    },
    () => clock.now,
  );
  return { queue, clock };
}

function submission(
  overrides: Partial<SbomJobSubmission> = {},
): SbomJobSubmission {
  return {
    tenantId: "tenant-a",
    repositoryId: "org/repo",
    scanId: "scan-1",
    contentHash: "hash-1",
    payload: "{}",
    ...overrides,
  };
}

function expectCode(fn: () => unknown, code: SbomErrorCode): void {
  try {
    fn();
  } catch (error) {
    expect((error as SbomIngestionError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("SbomJobQueue - enqueue", () => {
  it("assigns increasing revisions", () => {
    const { queue } = setup();
    const a = queue.enqueue(submission({ scanId: "s1" }));
    const b = queue.enqueue(submission({ scanId: "s2" }));
    expect(a.status).toBe("enqueued");
    expect(b.job.revision).toBeGreaterThan(a.job.revision);
  });

  it("returns the in-flight job for identical content", () => {
    const { queue } = setup();
    const first = queue.enqueue(submission());
    const again = queue.enqueue(submission());
    expect(again).toEqual({ status: "duplicate", job: first.job });
    expect(queue.stats().pending).toBe(1);
  });

  it("rejects different content for a scan that is in flight", () => {
    const { queue } = setup();
    queue.enqueue(submission());
    expectCode(
      () => queue.enqueue(submission({ contentHash: "hash-2" })),
      "CONFLICT",
    );
  });

  it("treats identical content after completion as a duplicate and new content as a new job", () => {
    const { queue } = setup();
    const first = queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    queue.complete(claim.job.jobId, "w1", claim.token);

    expect(queue.enqueue(submission()).status).toBe("duplicate");
    const replacement = queue.enqueue(submission({ contentHash: "hash-2" }));
    expect(replacement.status).toBe("enqueued");
    expect(replacement.job.jobId).not.toBe(first.job.jobId);
  });

  it("allows resubmission after dead-lettering", () => {
    const { queue } = setup();
    queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    queue.fail(claim.job.jobId, "w1", claim.token, "INVALID_DOCUMENT");
    expect(queue.enqueue(submission()).status).toBe("enqueued");
  });

  it("isolates identical scan ids across tenants", () => {
    const { queue } = setup();
    queue.enqueue(submission({ tenantId: "tenant-a" }));
    expect(
      queue.enqueue(submission({ tenantId: "tenant-b", contentHash: "other" }))
        .status,
    ).toBe("enqueued");
  });

  it("enforces global capacity at exactly maxPendingJobs", () => {
    const { queue } = setup({ maxPendingJobs: 2, maxPendingJobsPerTenant: 2 });
    queue.enqueue(submission({ scanId: "s1" }));
    queue.enqueue(submission({ scanId: "s2", tenantId: "tenant-b" }));
    expectCode(
      () => queue.enqueue(submission({ scanId: "s3", tenantId: "tenant-c" })),
      "QUEUE_FULL",
    );
  });

  it("enforces per-tenant capacity without starving other tenants", () => {
    const { queue } = setup({ maxPendingJobs: 10, maxPendingJobsPerTenant: 1 });
    queue.enqueue(submission({ scanId: "s1" }));
    expectCode(() => queue.enqueue(submission({ scanId: "s2" })), "QUEUE_FULL");
    expect(
      queue.enqueue(submission({ scanId: "s1", tenantId: "tenant-b" })).status,
    ).toBe("enqueued");
  });

  it("frees capacity when a job finishes", () => {
    const { queue } = setup({ maxPendingJobs: 1, maxPendingJobsPerTenant: 1 });
    queue.enqueue(submission({ scanId: "s1" }));
    const claim = queue.claim("w1")!;
    queue.complete(claim.job.jobId, "w1", claim.token);
    expect(queue.enqueue(submission({ scanId: "s2" })).status).toBe("enqueued");
  });
});

describe("SbomJobQueue - claiming", () => {
  it("hands each job to exactly one worker", () => {
    const { queue } = setup();
    queue.enqueue(submission());
    const first = queue.claim("w1");
    const second = queue.claim("w2");
    expect(first?.job.status).toBe("running");
    expect(first?.job.attempts).toBe(1);
    expect(second).toBeUndefined();
  });

  it("claims in submission order", () => {
    const { queue } = setup();
    const a = queue.enqueue(submission({ scanId: "a" }));
    const b = queue.enqueue(submission({ scanId: "b" }));
    expect(queue.claim("w1")?.job.jobId).toBe(a.job.jobId);
    expect(queue.claim("w2")?.job.jobId).toBe(b.job.jobId);
  });

  it("only lets the lease holder with the current token complete", () => {
    const { queue } = setup();
    queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    expect(queue.complete(claim.job.jobId, "w2", claim.token)).toBe(false);
    expect(queue.complete(claim.job.jobId, "w1", claim.token + 1)).toBe(false);
    expect(queue.complete(claim.job.jobId, "w1", claim.token)).toBe(true);
    expect(queue.complete(claim.job.jobId, "w1", claim.token)).toBe(false);
    expect(queue.get(claim.job.jobId)?.status).toBe("completed");
  });

  it("drops the payload once a job finishes", () => {
    const { queue } = setup();
    queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    queue.complete(claim.job.jobId, "w1", claim.token);
    expect(
      JSON.stringify(
        (queue as unknown as { entries: Map<string, unknown> }).entries.get(
          claim.job.jobId,
        ),
      ),
    ).not.toContain("payload");
  });

  it("validates the worker id", () => {
    const { queue } = setup();
    expect(() => queue.claim(" ")).toThrow(TypeError);
  });
});

describe("SbomJobQueue - leases and recovery", () => {
  it("recovers an expired lease and fences out the former holder", () => {
    const { queue, clock } = setup();
    queue.enqueue(submission());
    const stalled = queue.claim("w1")!;

    clock.now += 4_999;
    expect(queue.claim("w2")).toBeUndefined();

    clock.now += 1; // lease expires exactly at the TTL boundary
    expect(queue.recoverExpired()).toEqual([stalled.job.jobId]);
    expect(queue.get(stalled.job.jobId)).toMatchObject({
      status: "pending",
      lastErrorCode: "LEASE_EXPIRED",
    });

    clock.now += 100; // first retry backoff
    const takeover = queue.claim("w2")!;
    expect(takeover.job.attempts).toBe(2);
    expect(takeover.token).toBeGreaterThan(stalled.token);

    expect(queue.complete(stalled.job.jobId, "w1", stalled.token)).toBe(false);
    expect(
      queue.fail(stalled.job.jobId, "w1", stalled.token, "STORAGE_FAILURE"),
    ).toBe("stale");
    expect(queue.complete(takeover.job.jobId, "w2", takeover.token)).toBe(true);
  });

  it("dead-letters a job whose lease keeps expiring", () => {
    const { queue, clock } = setup({ maxAttempts: 2 });
    const { job } = queue.enqueue(submission());
    queue.claim("w1");
    clock.now += 5_000;
    queue.recoverExpired();
    clock.now += 100;
    queue.claim("w2");
    clock.now += 5_000;
    queue.recoverExpired();
    expect(queue.get(job.jobId)).toMatchObject({
      status: "dead_lettered",
      lastErrorCode: "LEASE_EXPIRED",
    });
  });

  it("renews only for the current holder", () => {
    const { queue, clock } = setup();
    queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    clock.now += 4_000;
    expect(queue.renew(claim.job.jobId, "w2", claim.token)).toBe(false);
    expect(queue.renew(claim.job.jobId, "w1", claim.token)).toBe(true);
    clock.now += 4_000;
    expect(queue.recoverExpired()).toEqual([]);
    expect(queue.complete(claim.job.jobId, "w1", claim.token)).toBe(true);
  });
});

describe("SbomJobQueue - retries", () => {
  it("retries retryable failures with exponential backoff, then dead-letters", () => {
    const { queue, clock } = setup({
      maxAttempts: 3,
      retryBackoffMs: 100,
      maxRetryBackoffMs: 150,
    });
    const { job } = queue.enqueue(submission());

    let claim = queue.claim("w1")!;
    expect(queue.fail(job.jobId, "w1", claim.token, "STORAGE_FAILURE")).toBe(
      "retry_scheduled",
    );
    expect(queue.get(job.jobId)?.availableAt).toBe(clock.now + 100);
    clock.now += 99;
    expect(queue.claim("w1")).toBeUndefined();
    clock.now += 1;

    claim = queue.claim("w1")!;
    expect(queue.fail(job.jobId, "w1", claim.token, "STORAGE_FAILURE")).toBe(
      "retry_scheduled",
    );
    expect(queue.get(job.jobId)?.availableAt).toBe(clock.now + 150); // capped
    clock.now += 150;

    claim = queue.claim("w1")!;
    expect(claim.job.attempts).toBe(3);
    expect(queue.fail(job.jobId, "w1", claim.token, "STORAGE_FAILURE")).toBe(
      "dead_lettered",
    );
    expect(queue.get(job.jobId)).toMatchObject({
      status: "dead_lettered",
      attempts: 3,
    });
  });

  it("dead-letters non-retryable failures immediately", () => {
    const { queue } = setup();
    const { job } = queue.enqueue(submission());
    const claim = queue.claim("w1")!;
    expect(queue.fail(job.jobId, "w1", claim.token, "UNSUPPORTED_FORMAT")).toBe(
      "dead_lettered",
    );
    expect(queue.get(job.jobId)?.attempts).toBe(1);
  });
});

describe("SbomJobQueue - retention", () => {
  it("prunes finished jobs after the retention window and keeps in-flight ones", () => {
    const { queue, clock } = setup({ finishedJobRetentionMs: 1_000 });
    queue.enqueue(submission({ scanId: "done" }));
    const pending = queue.enqueue(submission({ scanId: "waiting" }));
    const claim = queue.claim("w1")!;
    queue.complete(claim.job.jobId, "w1", claim.token);

    clock.now += 999;
    expect(queue.prune()).toBe(0);
    clock.now += 1;
    expect(queue.prune()).toBe(1);
    expect(queue.get(claim.job.jobId)).toBeUndefined();
    expect(queue.get(pending.job.jobId)?.status).toBe("pending");
    expect(queue.size()).toBe(1);
  });
});
