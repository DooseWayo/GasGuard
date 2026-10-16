/**
 * Work queue for SBOM ingestion jobs.
 *
 * One job per `(tenantId, repositoryId, scanId)` may be in flight at a time.
 * Workers claim jobs under a lease from `ScanLeaseManager`; the lease's fencing
 * token must be presented to complete or fail the job, so a worker whose lease
 * expired (and whose job was handed to someone else) cannot complete it.
 *
 * Failure semantics:
 * - Retryable failures (and expired leases) return the job to `pending` with
 *   exponential backoff until `maxAttempts` claims have been made.
 * - Non-retryable failures, and retryable ones that run out of attempts, move
 *   the job to `dead_lettered` with the last error code.
 * - An attempt is counted when a job is claimed, not when it fails, so a
 *   document that crashes its worker every time still dead-letters.
 *
 * Memory is bounded: at most `maxPendingJobs` jobs (and their payloads) are in
 * flight, payloads are dropped as soon as a job finishes, and finished job
 * records are pruned after `finishedJobRetentionMs`.
 */

import * as crypto from "crypto";
import { ScanLeaseManager } from "../queue/scan-lease";
import { SbomIngestionConfig } from "./sbom-config";
import {
  SbomErrorCode,
  SbomIngestionError,
  isRetryableSbomError,
} from "./sbom-types";

export type SbomJobStatus =
  | "pending"
  | "running"
  | "completed"
  | "dead_lettered";

export interface SbomJob {
  jobId: string;
  tenantId: string;
  repositoryId: string;
  scanId: string;
  contentHash: string;
  /** Submission sequence number; orders writes to the store. */
  revision: number;
  status: SbomJobStatus;
  /** Claims made so far, including one currently running. */
  attempts: number;
  /** Earliest time a pending job may be claimed. */
  availableAt: number;
  createdAt: number;
  updatedAt: number;
  finishedAt?: number;
  lastErrorCode?: SbomErrorCode;
}

export interface SbomJobSubmission {
  tenantId: string;
  repositoryId: string;
  scanId: string;
  contentHash: string;
  payload: string | Buffer;
}

export type SbomEnqueueResult =
  | { status: "enqueued"; job: SbomJob }
  | { status: "duplicate"; job: SbomJob };

export interface SbomJobClaim {
  job: SbomJob;
  payload: string | Buffer;
  /** Fencing token proving ownership; required by complete/fail/renew. */
  token: number;
}

export type SbomFailOutcome = "retry_scheduled" | "dead_lettered" | "stale";

export interface SbomQueueStats {
  pending: number;
  running: number;
  completed: number;
  deadLettered: number;
}

type QueueLimits = Pick<
  SbomIngestionConfig,
  | "maxAttempts"
  | "retryBackoffMs"
  | "maxRetryBackoffMs"
  | "leaseTtlMs"
  | "maxPendingJobs"
  | "maxPendingJobsPerTenant"
  | "finishedJobRetentionMs"
>;

interface QueueEntry {
  job: SbomJob;
  /** Present only while the job is pending or running. */
  payload?: string | Buffer;
  /** Worker holding the job while running. */
  owner?: string;
}

export class SbomJobQueue {
  private readonly limits: QueueLimits;
  private readonly clock: () => number;
  private readonly leases: ScanLeaseManager;
  /** Insertion-ordered, so iteration is FIFO by submission. */
  private readonly entries: Map<string, QueueEntry> = new Map();
  /** Most recent job per scan, used for de-duplication and conflicts. */
  private readonly latestByScan: Map<string, string> = new Map();
  private readonly activeByTenant: Map<string, number> = new Map();
  private activeTotal = 0;
  private sequence = 0;

  constructor(limits: QueueLimits, clock: () => number = Date.now) {
    this.limits = limits;
    this.clock = clock;
    this.leases = new ScanLeaseManager(limits.leaseTtlMs, clock);
  }

  /**
   * Add a job for a scan's SBOM.
   *
   * Resubmitting identical content for a scan that is in flight or already
   * completed returns the existing job (`duplicate`). Submitting different
   * content while a job for that scan is in flight throws CONFLICT. After a job
   * completes or dead-letters, new content for the scan is accepted.
   *
   * @throws SbomIngestionError QUEUE_FULL when global or tenant capacity is
   *   exhausted (retryable), or CONFLICT.
   */
  enqueue(submission: SbomJobSubmission): SbomEnqueueResult {
    const now = this.clock();
    this.prune(now);
    const scanKey = scanKeyOf(
      submission.tenantId,
      submission.repositoryId,
      submission.scanId,
    );

    const latestId = this.latestByScan.get(scanKey);
    const latest = latestId ? this.entries.get(latestId)?.job : undefined;
    if (latest) {
      const sameContent = latest.contentHash === submission.contentHash;
      const inFlight =
        latest.status === "pending" || latest.status === "running";
      if (sameContent && (inFlight || latest.status === "completed")) {
        return { status: "duplicate", job: { ...latest } };
      }
      if (inFlight) {
        throw new SbomIngestionError(
          "CONFLICT",
          "A different SBOM is already being ingested for this scan",
        );
      }
    }

    if (this.activeTotal >= this.limits.maxPendingJobs) {
      throw new SbomIngestionError(
        "QUEUE_FULL",
        "SBOM ingestion queue is full; retry later",
      );
    }
    if (
      (this.activeByTenant.get(submission.tenantId) ?? 0) >=
      this.limits.maxPendingJobsPerTenant
    ) {
      throw new SbomIngestionError(
        "QUEUE_FULL",
        "Tenant has too many SBOM ingestion jobs in flight; retry later",
      );
    }

    const revision = ++this.sequence;
    const job: SbomJob = {
      jobId: `sbom_${crypto.randomUUID()}`,
      tenantId: submission.tenantId,
      repositoryId: submission.repositoryId,
      scanId: submission.scanId,
      contentHash: submission.contentHash,
      revision,
      status: "pending",
      attempts: 0,
      availableAt: now,
      createdAt: now,
      updatedAt: now,
    };
    this.entries.set(job.jobId, { job, payload: submission.payload });
    this.latestByScan.set(scanKey, job.jobId);
    this.activeTotal++;
    this.activeByTenant.set(
      job.tenantId,
      (this.activeByTenant.get(job.tenantId) ?? 0) + 1,
    );
    return { status: "enqueued", job: { ...job } };
  }

  /**
   * Claim the oldest runnable job for `workerId`, or undefined when none is due.
   *
   * Jobs whose lease has expired are recovered first, so an interrupted job
   * becomes claimable again after its backoff.
   */
  claim(workerId: string): SbomJobClaim | undefined {
    requireNonEmpty(workerId, "workerId");
    const now = this.clock();
    this.recoverExpired();
    this.prune(now);

    for (const entry of this.entries.values()) {
      const { job } = entry;
      if (job.status !== "pending" || job.availableAt > now) {
        continue;
      }
      const lease = this.leases.acquire(job.jobId, workerId);
      if (!lease.granted) {
        // Unreachable while the queue is the only lease user; skip defensively.
        continue;
      }
      job.status = "running";
      job.attempts++;
      job.updatedAt = now;
      entry.owner = workerId;
      return {
        job: { ...job },
        payload: entry.payload as string | Buffer,
        token: lease.lease.token,
      };
    }
    return undefined;
  }

  /** True while `workerId` still holds the job's live lease with `token`. */
  isCurrent(jobId: string, workerId: string, token: number): boolean {
    const entry = this.entries.get(jobId);
    const lease = this.leases.get(jobId);
    return (
      entry?.job.status === "running" &&
      entry.owner === workerId &&
      lease?.owner === workerId &&
      lease.token === token
    );
  }

  /** Extend the lease of a running job; false if the caller no longer owns it. */
  renew(jobId: string, workerId: string, token: number): boolean {
    if (!this.isCurrent(jobId, workerId, token)) {
      return false;
    }
    return this.leases.renew(jobId, workerId, token);
  }

  /** Mark a running job completed. Returns false for a stale or unknown claim. */
  complete(jobId: string, workerId: string, token: number): boolean {
    if (!this.isCurrent(jobId, workerId, token)) {
      return false;
    }
    const entry = this.entries.get(jobId) as QueueEntry;
    this.leases.release(jobId, workerId, token);
    this.finish(entry, "completed");
    return true;
  }

  /**
   * Record a failed attempt. Retryable codes are rescheduled with backoff while
   * attempts remain; everything else is dead-lettered.
   */
  fail(
    jobId: string,
    workerId: string,
    token: number,
    code: SbomErrorCode,
  ): SbomFailOutcome {
    if (!this.isCurrent(jobId, workerId, token)) {
      return "stale";
    }
    const entry = this.entries.get(jobId) as QueueEntry;
    this.leases.release(jobId, workerId, token);
    entry.job.lastErrorCode = code;
    if (
      isRetryableSbomError(code) &&
      entry.job.attempts < this.limits.maxAttempts
    ) {
      this.reschedule(entry);
      return "retry_scheduled";
    }
    this.finish(entry, "dead_lettered");
    return "dead_lettered";
  }

  /**
   * Return running jobs whose lease expired to the queue, or dead-letter them
   * when no attempts remain. Returns the affected job ids.
   */
  recoverExpired(): string[] {
    const recovered: string[] = [];
    for (const entry of this.entries.values()) {
      if (entry.job.status !== "running" || this.leases.get(entry.job.jobId)) {
        continue;
      }
      entry.job.lastErrorCode = "LEASE_EXPIRED";
      if (entry.job.attempts < this.limits.maxAttempts) {
        this.reschedule(entry);
      } else {
        this.finish(entry, "dead_lettered");
      }
      recovered.push(entry.job.jobId);
    }
    this.leases.reclaimExpired();
    return recovered;
  }

  get(jobId: string): SbomJob | undefined {
    const job = this.entries.get(jobId)?.job;
    return job ? { ...job } : undefined;
  }

  stats(): SbomQueueStats {
    const stats: SbomQueueStats = {
      pending: 0,
      running: 0,
      completed: 0,
      deadLettered: 0,
    };
    for (const { job } of this.entries.values()) {
      if (job.status === "pending") stats.pending++;
      else if (job.status === "running") stats.running++;
      else if (job.status === "completed") stats.completed++;
      else stats.deadLettered++;
    }
    return stats;
  }

  /** Total job records held, in flight or finished. */
  size(): number {
    return this.entries.size;
  }

  /** Drop finished job records older than the retention window. */
  prune(now: number = this.clock()): number {
    let removed = 0;
    for (const [jobId, entry] of this.entries) {
      const { finishedAt } = entry.job;
      if (
        finishedAt === undefined ||
        now < finishedAt + this.limits.finishedJobRetentionMs
      ) {
        continue;
      }
      this.entries.delete(jobId);
      const scanKey = scanKeyOf(
        entry.job.tenantId,
        entry.job.repositoryId,
        entry.job.scanId,
      );
      if (this.latestByScan.get(scanKey) === jobId) {
        this.latestByScan.delete(scanKey);
      }
      removed++;
    }
    return removed;
  }

  private reschedule(entry: QueueEntry): void {
    const now = this.clock();
    const exponent = Math.max(0, entry.job.attempts - 1);
    const delay = Math.min(
      this.limits.maxRetryBackoffMs,
      this.limits.retryBackoffMs * 2 ** exponent,
    );
    entry.job.status = "pending";
    entry.job.availableAt = now + delay;
    entry.job.updatedAt = now;
    entry.owner = undefined;
  }

  private finish(
    entry: QueueEntry,
    status: "completed" | "dead_lettered",
  ): void {
    const now = this.clock();
    entry.job.status = status;
    entry.job.finishedAt = now;
    entry.job.updatedAt = now;
    entry.owner = undefined;
    entry.payload = undefined;
    this.activeTotal = Math.max(0, this.activeTotal - 1);
    const remaining = (this.activeByTenant.get(entry.job.tenantId) ?? 1) - 1;
    if (remaining <= 0) {
      this.activeByTenant.delete(entry.job.tenantId);
    } else {
      this.activeByTenant.set(entry.job.tenantId, remaining);
    }
  }
}

function scanKeyOf(
  tenantId: string,
  repositoryId: string,
  scanId: string,
): string {
  return `${tenantId}\u0000${repositoryId}\u0000${scanId}`;
}

function requireNonEmpty(value: string, field: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${field} must be a non-empty string`);
  }
}
