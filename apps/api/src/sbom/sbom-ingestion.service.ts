/**
 * SBOM ingestion for repository scans.
 *
 * The API layer calls `submit` with the raw SBOM a repository supplied for a
 * scan; workers call `processNext` to parse, normalize, and persist it; the
 * reporting layer reads results back with `getResult`. Each boundary is
 * tenant-scoped: a caller can only see jobs and results for the tenant id it
 * passes.
 *
 * Submission does cheap checks only (identifiers, size, capacity, duplicates)
 * so API latency does not depend on document size. Format and content errors
 * surface on the job (`getJob(...).lastErrorCode`) once a worker has run it.
 */

import {
  DEFAULT_SBOM_INGESTION_CONFIG,
  SbomIngestionConfig,
  resolveSbomIngestionConfig,
} from "./sbom-config";
import { SbomJob, SbomJobQueue, SbomQueueStats } from "./sbom-job-queue";
import {
  SbomIngestionMetrics,
  SbomLogger,
  consoleSbomLogger,
  sanitizeLogFields,
} from "./sbom-metrics";
import {
  computeSbomContentHash,
  parseSbom,
  sbomByteLength,
} from "./sbom-parser";
import { SbomStore, StoredSbom } from "./sbom-store";
import {
  NormalizedSbom,
  SbomErrorCode,
  SbomIngestionError,
} from "./sbom-types";

export interface SbomSubmitRequest {
  tenantId: string;
  repositoryId: string;
  scanId: string;
  /** Raw CycloneDX JSON or SPDX JSON document. */
  document: string | Buffer;
}

export interface SbomSubmitResult {
  /** `duplicate` when identical content was already accepted for this scan. */
  status: "accepted" | "duplicate";
  jobId: string;
  contentHash: string;
  jobStatus: SbomJob["status"];
}

export type SbomProcessOutcome =
  | { status: "idle" }
  | {
      status: "completed";
      jobId: string;
      components: number;
      superseded: boolean;
    }
  | { status: "retry_scheduled"; jobId: string; code: SbomErrorCode }
  | { status: "dead_lettered"; jobId: string; code: SbomErrorCode }
  | { status: "stale"; jobId: string };

export interface SbomIngestionServiceOptions {
  store: SbomStore;
  config?: Partial<SbomIngestionConfig>;
  logger?: SbomLogger;
  metrics?: SbomIngestionMetrics;
  clock?: () => number;
}

/** Tenant, repository, and scan ids: 1-256 chars, no whitespace or control chars. */
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;

export class SbomIngestionService {
  readonly config: SbomIngestionConfig;
  readonly metrics: SbomIngestionMetrics;
  private readonly store: SbomStore;
  private readonly queue: SbomJobQueue;
  private readonly logger: SbomLogger;
  private readonly clock: () => number;

  constructor(options: SbomIngestionServiceOptions) {
    this.config = resolveSbomIngestionConfig(
      options.config ?? DEFAULT_SBOM_INGESTION_CONFIG,
    );
    this.store = options.store;
    // Sanitize here as well as in the default logger, so a custom logger can
    // never receive more than identifiers, counts, and codes.
    const logger = options.logger ?? consoleSbomLogger;
    this.logger = {
      log: (level, event, fields) =>
        logger.log(level, event, sanitizeLogFields(fields)),
    };
    this.metrics = options.metrics ?? new SbomIngestionMetrics();
    this.clock = options.clock ?? Date.now;
    this.queue = new SbomJobQueue(this.config, this.clock);
  }

  /**
   * Accept an SBOM for asynchronous ingestion.
   *
   * @throws SbomIngestionError INGESTION_DISABLED, INVALID_REQUEST,
   *   DOCUMENT_TOO_LARGE, CONFLICT, or QUEUE_FULL (the only retryable one).
   */
  async submit(request: SbomSubmitRequest): Promise<SbomSubmitResult> {
    try {
      if (!this.config.enabled) {
        throw new SbomIngestionError(
          "INGESTION_DISABLED",
          "SBOM ingestion is disabled",
        );
      }
      requireIdentifier(request?.tenantId, "tenantId");
      requireIdentifier(request.repositoryId, "repositoryId");
      requireIdentifier(request.scanId, "scanId");
      if (
        typeof request.document !== "string" &&
        !Buffer.isBuffer(request.document)
      ) {
        throw new SbomIngestionError(
          "INVALID_REQUEST",
          "document must be a string or Buffer",
        );
      }
      const bytes = sbomByteLength(request.document);
      if (bytes === 0) {
        throw new SbomIngestionError("INVALID_REQUEST", "document is empty");
      }
      if (bytes > this.config.maxDocumentBytes) {
        throw new SbomIngestionError(
          "DOCUMENT_TOO_LARGE",
          `SBOM document exceeds ${this.config.maxDocumentBytes} bytes`,
        );
      }

      const contentHash = computeSbomContentHash(request.document);
      const result = this.queue.enqueue({
        tenantId: request.tenantId,
        repositoryId: request.repositoryId,
        scanId: request.scanId,
        contentHash,
        payload: request.document,
      });
      const status = result.status === "enqueued" ? "accepted" : "duplicate";
      this.metrics.recordSubmission(status);
      this.logger.log("info", "sbom.submitted", {
        tenantId: request.tenantId,
        repositoryId: request.repositoryId,
        scanId: request.scanId,
        jobId: result.job.jobId,
        outcome: status,
        bytes,
        contentHash: shortHash(contentHash),
      });
      return {
        status,
        jobId: result.job.jobId,
        contentHash,
        jobStatus: result.job.status,
      };
    } catch (error) {
      const code =
        error instanceof SbomIngestionError ? error.code : "INVALID_REQUEST";
      this.metrics.recordSubmission("rejected", code);
      this.logger.log("warn", "sbom.submission_rejected", {
        tenantId: safeIdentifier(request?.tenantId),
        repositoryId: safeIdentifier(request?.repositoryId),
        scanId: safeIdentifier(request?.scanId),
        code,
      });
      throw error;
    }
  }

  /**
   * Claim and run the next due job as `workerId`.
   *
   * Never throws for job-level failures; the outcome reports what happened.
   * A `stale` outcome means the worker lost its lease mid-job; the job has been
   * or will be re-run by another worker, and any result this worker already
   * stored is identical to what the new owner will write.
   */
  async processNext(workerId: string): Promise<SbomProcessOutcome> {
    const recovered = this.queue.recoverExpired();
    if (recovered.length > 0) {
      this.metrics.recordLeasesRecovered(recovered.length);
      this.logger.log("warn", "sbom.leases_recovered", {
        count: recovered.length,
      });
    }

    const claim = this.queue.claim(workerId);
    if (!claim) {
      return { status: "idle" };
    }
    const { job, token } = claim;
    const startedAt = this.clock();

    let sbom: NormalizedSbom;
    try {
      sbom = parseSbom(claim.payload, this.config);
    } catch (error) {
      // Non-SbomIngestionErrors here are parser defects or engine limits (e.g.
      // a RangeError); retrying the same bytes would fail the same way.
      const code =
        error instanceof SbomIngestionError ? error.code : "INVALID_DOCUMENT";
      return this.failJob(job, workerId, token, code, startedAt);
    }

    if (!this.queue.isCurrent(job.jobId, workerId, token)) {
      return this.staleJob(job, workerId);
    }

    let superseded: boolean;
    try {
      const write = await this.store.put({
        tenantId: job.tenantId,
        repositoryId: job.repositoryId,
        scanId: job.scanId,
        jobId: job.jobId,
        revision: job.revision,
        ingestedAt: this.clock(),
        sbom,
      });
      superseded = write === "stale";
    } catch {
      return this.failJob(job, workerId, token, "STORAGE_FAILURE", startedAt);
    }

    if (!this.queue.complete(job.jobId, workerId, token)) {
      return this.staleJob(job, workerId);
    }
    const durationMs = this.clock() - startedAt;
    this.metrics.recordCompleted(
      durationMs,
      sbom.stats.accepted,
      sbom.stats.rejected,
    );
    this.logger.log("info", "sbom.ingested", {
      tenantId: job.tenantId,
      repositoryId: job.repositoryId,
      scanId: job.scanId,
      jobId: job.jobId,
      workerId,
      attempt: job.attempts,
      format: sbom.format,
      specVersion: sbom.specVersion,
      components: sbom.stats.accepted,
      rejectedComponents: sbom.stats.rejected,
      duplicateComponents: sbom.stats.duplicates,
      contentHash: shortHash(sbom.contentHash),
      superseded,
      durationMs,
    });
    return {
      status: "completed",
      jobId: job.jobId,
      components: sbom.stats.accepted,
      superseded,
    };
  }

  /** Run jobs until the queue has nothing due or `maxJobs` have been handled. */
  async drain(
    workerId: string,
    maxJobs = Number.POSITIVE_INFINITY,
  ): Promise<SbomProcessOutcome[]> {
    const outcomes: SbomProcessOutcome[] = [];
    while (outcomes.length < maxJobs) {
      const outcome = await this.processNext(workerId);
      if (outcome.status === "idle") {
        break;
      }
      outcomes.push(outcome);
    }
    return outcomes;
  }

  /** The job, if it exists and belongs to `tenantId`. */
  getJob(tenantId: string, jobId: string): SbomJob | undefined {
    const job = this.queue.get(jobId);
    return job && job.tenantId === tenantId ? job : undefined;
  }

  getResult(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<StoredSbom | undefined> {
    return this.store.get(tenantId, repositoryId, scanId);
  }

  queueStats(): SbomQueueStats {
    return this.queue.stats();
  }

  /** Prometheus exposition of ingestion counters and current queue depth. */
  metricsText(): string {
    return this.metrics.toPrometheus(this.queue.stats());
  }

  /** Job records held in memory, in flight or within the retention window. */
  queueSize(): number {
    return this.queue.size();
  }

  private failJob(
    job: SbomJob,
    workerId: string,
    token: number,
    code: SbomErrorCode,
    startedAt: number,
  ): SbomProcessOutcome {
    const outcome = this.queue.fail(job.jobId, workerId, token, code);
    if (outcome === "stale") {
      return this.staleJob(job, workerId);
    }
    this.metrics.recordFailure(code, outcome, this.clock() - startedAt);
    this.logger.log(
      outcome === "dead_lettered" ? "error" : "warn",
      "sbom.ingest_failed",
      {
        tenantId: job.tenantId,
        repositoryId: job.repositoryId,
        scanId: job.scanId,
        jobId: job.jobId,
        workerId,
        attempt: job.attempts,
        maxAttempts: this.config.maxAttempts,
        code,
        outcome,
      },
    );
    return { status: outcome, jobId: job.jobId, code };
  }

  private staleJob(job: SbomJob, workerId: string): SbomProcessOutcome {
    this.metrics.recordStale();
    this.logger.log("warn", "sbom.lease_lost", {
      tenantId: job.tenantId,
      scanId: job.scanId,
      jobId: job.jobId,
      workerId,
      attempt: job.attempts,
    });
    return { status: "stale", jobId: job.jobId };
  }
}

function requireIdentifier(value: unknown, field: string): void {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new SbomIngestionError(
      "INVALID_REQUEST",
      `${field} must be 1-256 characters of letters, digits, or ._:/@-`,
    );
  }
}

/** Echo an identifier into logs only when it is well-formed. */
function safeIdentifier(value: unknown): string | undefined {
  return typeof value === "string" && IDENTIFIER_PATTERN.test(value)
    ? value
    : undefined;
}

function shortHash(hash: string): string {
  return hash.slice(0, 12);
}
