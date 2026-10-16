/**
 * Metrics and structured logging for SBOM ingestion.
 *
 * Labels are drawn from closed sets (outcomes and error codes), never from
 * tenant, repository, or document data, so metric cardinality stays bounded and
 * no customer content leaks into a metrics backend.
 *
 * Log fields pass through `sanitizeLogFields`, which keeps only primitive
 * values, truncates long strings, and drops keys that look like they carry
 * payloads or credentials. The service only ever logs identifiers, counts,
 * error codes, and a truncated content hash.
 */

import type { SbomQueueStats } from "./sbom-job-queue";

export interface SbomMetricsSnapshot {
  submissions: Record<string, number>;
  submissionRejections: Record<string, number>;
  jobsCompleted: number;
  jobFailures: Record<string, number>;
  jobsRetried: number;
  jobsDeadLettered: number;
  staleCompletions: number;
  leasesRecovered: number;
  componentsIngested: number;
  componentsRejected: number;
  ingestDurationMs: { count: number; sum: number; max: number };
}

export class SbomIngestionMetrics {
  private readonly submissions: Map<string, number> = new Map();
  private readonly submissionRejections: Map<string, number> = new Map();
  private readonly jobFailures: Map<string, number> = new Map();
  private jobsCompleted = 0;
  private jobsRetried = 0;
  private jobsDeadLettered = 0;
  private staleCompletions = 0;
  private leasesRecovered = 0;
  private componentsIngested = 0;
  private componentsRejected = 0;
  private durationCount = 0;
  private durationSum = 0;
  private durationMax = 0;

  recordSubmission(
    outcome: "accepted" | "duplicate" | "rejected",
    errorCode?: string,
  ): void {
    increment(this.submissions, outcome);
    if (outcome === "rejected" && errorCode) {
      increment(this.submissionRejections, errorCode);
    }
  }

  recordCompleted(
    durationMs: number,
    accepted: number,
    rejected: number,
  ): void {
    this.jobsCompleted++;
    this.componentsIngested += accepted;
    this.componentsRejected += rejected;
    this.recordDuration(durationMs);
  }

  recordFailure(
    errorCode: string,
    outcome: "retry_scheduled" | "dead_lettered",
    durationMs: number,
  ): void {
    increment(this.jobFailures, errorCode);
    if (outcome === "retry_scheduled") {
      this.jobsRetried++;
    } else {
      this.jobsDeadLettered++;
    }
    this.recordDuration(durationMs);
  }

  recordStale(): void {
    this.staleCompletions++;
  }

  recordLeasesRecovered(count: number): void {
    this.leasesRecovered += count;
  }

  snapshot(): SbomMetricsSnapshot {
    return {
      submissions: Object.fromEntries(this.submissions),
      submissionRejections: Object.fromEntries(this.submissionRejections),
      jobsCompleted: this.jobsCompleted,
      jobFailures: Object.fromEntries(this.jobFailures),
      jobsRetried: this.jobsRetried,
      jobsDeadLettered: this.jobsDeadLettered,
      staleCompletions: this.staleCompletions,
      leasesRecovered: this.leasesRecovered,
      componentsIngested: this.componentsIngested,
      componentsRejected: this.componentsRejected,
      ingestDurationMs: {
        count: this.durationCount,
        sum: this.durationSum,
        max: this.durationMax,
      },
    };
  }

  /** Prometheus text exposition of the counters, plus optional queue gauges. */
  toPrometheus(queue?: Partial<SbomQueueStats>): string {
    const lines: string[] = [];
    const counter = (name: string, help: string) => {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} counter`);
    };
    counter("gasguard_sbom_submissions_total", "SBOM submissions by outcome.");
    for (const [outcome, value] of this.submissions) {
      lines.push(
        `gasguard_sbom_submissions_total{outcome="${outcome}"} ${value}`,
      );
    }
    counter(
      "gasguard_sbom_submission_rejections_total",
      "Rejected SBOM submissions by error code.",
    );
    for (const [code, value] of this.submissionRejections) {
      lines.push(
        `gasguard_sbom_submission_rejections_total{code="${code}"} ${value}`,
      );
    }
    counter(
      "gasguard_sbom_jobs_completed_total",
      "SBOM ingestion jobs completed.",
    );
    lines.push(`gasguard_sbom_jobs_completed_total ${this.jobsCompleted}`);
    counter(
      "gasguard_sbom_job_failures_total",
      "Failed SBOM ingestion attempts by error code.",
    );
    for (const [code, value] of this.jobFailures) {
      lines.push(`gasguard_sbom_job_failures_total{code="${code}"} ${value}`);
    }
    counter(
      "gasguard_sbom_jobs_dead_lettered_total",
      "SBOM ingestion jobs dead-lettered.",
    );
    lines.push(
      `gasguard_sbom_jobs_dead_lettered_total ${this.jobsDeadLettered}`,
    );
    counter(
      "gasguard_sbom_stale_completions_total",
      "Completions rejected because the lease was lost.",
    );
    lines.push(
      `gasguard_sbom_stale_completions_total ${this.staleCompletions}`,
    );
    counter(
      "gasguard_sbom_leases_recovered_total",
      "Expired leases returned to the queue.",
    );
    lines.push(`gasguard_sbom_leases_recovered_total ${this.leasesRecovered}`);
    counter(
      "gasguard_sbom_components_ingested_total",
      "Components stored from ingested SBOMs.",
    );
    lines.push(
      `gasguard_sbom_components_ingested_total ${this.componentsIngested}`,
    );
    counter(
      "gasguard_sbom_components_rejected_total",
      "Invalid components skipped during ingestion.",
    );
    lines.push(
      `gasguard_sbom_components_rejected_total ${this.componentsRejected}`,
    );
    if (queue) {
      lines.push(
        "# HELP gasguard_sbom_queue_jobs SBOM ingestion jobs by status.",
        "# TYPE gasguard_sbom_queue_jobs gauge",
      );
      for (const [status, value] of Object.entries(queue)) {
        lines.push(`gasguard_sbom_queue_jobs{status="${status}"} ${value}`);
      }
    }
    return `${lines.join("\n")}\n`;
  }

  private recordDuration(durationMs: number): void {
    const value = Math.max(0, durationMs);
    this.durationCount++;
    this.durationSum += value;
    this.durationMax = Math.max(this.durationMax, value);
  }
}

export type SbomLogLevel = "info" | "warn" | "error";
export type SbomLogFields = Record<
  string,
  string | number | boolean | undefined
>;

export interface SbomLogger {
  log(level: SbomLogLevel, event: string, fields: SbomLogFields): void;
}

/** Emits one JSON object per line on stdout/stderr. */
export const consoleSbomLogger: SbomLogger = {
  log(level, event, fields) {
    const line = JSON.stringify({
      level,
      component: "sbom-ingestion",
      event,
      ...sanitizeLogFields(fields),
    });
    if (level === "info") {
      console.log(line);
    } else {
      console.error(line);
    }
  },
};

const MAX_LOG_STRING = 200;
/** Keys that must never reach a log line, even if a caller passes them. */
const FORBIDDEN_LOG_KEY =
  /payload|document|content(?!Hash)|body|secret|token|password|key|credential|authorization/i;

export function sanitizeLogFields(
  fields: Record<string, unknown>,
): SbomLogFields {
  const safe: SbomLogFields = {};
  for (const [key, value] of Object.entries(fields)) {
    if (FORBIDDEN_LOG_KEY.test(key)) {
      continue;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      safe[key] = value;
    } else if (typeof value === "string") {
      safe[key] =
        value.length > MAX_LOG_STRING
          ? `${value.slice(0, MAX_LOG_STRING)}…`
          : value;
    }
  }
  return safe;
}

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}
