/**
 * Configuration surface for SBOM ingestion.
 *
 * Every limit has a conservative default so the feature is safe to enable
 * without tuning. Values are validated once at construction; an invalid value
 * fails fast with a `RangeError` naming the offending option rather than
 * silently falling back.
 */

export interface SbomIngestionConfig {
  /** Master switch. When false, submissions are refused with INGESTION_DISABLED. */
  enabled: boolean;
  /** Largest accepted document, in bytes of UTF-8. */
  maxDocumentBytes: number;
  /** Largest number of component entries (including nested and rejected ones). */
  maxComponents: number;
  /** Deepest allowed nesting of CycloneDX `components` arrays. */
  maxNestingDepth: number;
  /**
   * Largest fraction (0-1) of components that may be rejected while the
   * document is still accepted. `0` makes any invalid component fatal.
   */
  maxRejectedRatio: number;
  /** Cap on rejection details kept per document (counts are always exact). */
  maxReportedRejections: number;
  /** Total attempts per job, including the first, before dead-lettering. */
  maxAttempts: number;
  /** Delay before the first retry; doubles on each further attempt. */
  retryBackoffMs: number;
  /** Upper bound on the retry delay. */
  maxRetryBackoffMs: number;
  /** How long a worker may hold a job before another worker can take it over. */
  leaseTtlMs: number;
  /** Pending plus running jobs across all tenants. */
  maxPendingJobs: number;
  /** Pending plus running jobs for a single tenant. */
  maxPendingJobsPerTenant: number;
  /** How long completed or dead-lettered job records stay queryable. */
  finishedJobRetentionMs: number;
}

export const DEFAULT_SBOM_INGESTION_CONFIG: Readonly<SbomIngestionConfig> =
  Object.freeze({
    enabled: true,
    maxDocumentBytes: 10 * 1024 * 1024,
    maxComponents: 50_000,
    maxNestingDepth: 16,
    maxRejectedRatio: 0.1,
    maxReportedRejections: 100,
    maxAttempts: 3,
    retryBackoffMs: 1_000,
    maxRetryBackoffMs: 60_000,
    leaseTtlMs: 60_000,
    maxPendingJobs: 1_000,
    maxPendingJobsPerTenant: 100,
    finishedJobRetentionMs: 60 * 60 * 1000,
  });

const ENV_KEYS: Record<keyof SbomIngestionConfig, string> = {
  enabled: "SBOM_INGESTION_ENABLED",
  maxDocumentBytes: "SBOM_MAX_DOCUMENT_BYTES",
  maxComponents: "SBOM_MAX_COMPONENTS",
  maxNestingDepth: "SBOM_MAX_NESTING_DEPTH",
  maxRejectedRatio: "SBOM_MAX_REJECTED_RATIO",
  maxReportedRejections: "SBOM_MAX_REPORTED_REJECTIONS",
  maxAttempts: "SBOM_MAX_ATTEMPTS",
  retryBackoffMs: "SBOM_RETRY_BACKOFF_MS",
  maxRetryBackoffMs: "SBOM_MAX_RETRY_BACKOFF_MS",
  leaseTtlMs: "SBOM_LEASE_TTL_MS",
  maxPendingJobs: "SBOM_MAX_PENDING_JOBS",
  maxPendingJobsPerTenant: "SBOM_MAX_PENDING_JOBS_PER_TENANT",
  finishedJobRetentionMs: "SBOM_FINISHED_JOB_RETENTION_MS",
};

/** Merge `overrides` over the defaults and validate the result. */
export function resolveSbomIngestionConfig(
  overrides: Partial<SbomIngestionConfig> = {},
): SbomIngestionConfig {
  const config: SbomIngestionConfig = {
    ...DEFAULT_SBOM_INGESTION_CONFIG,
    ...stripUndefined(overrides),
  };

  if (typeof config.enabled !== "boolean") {
    throw new RangeError("enabled must be a boolean");
  }
  requirePositiveInteger(config.maxDocumentBytes, "maxDocumentBytes");
  requirePositiveInteger(config.maxComponents, "maxComponents");
  requirePositiveInteger(config.maxNestingDepth, "maxNestingDepth");
  requireNonNegativeInteger(
    config.maxReportedRejections,
    "maxReportedRejections",
  );
  requirePositiveInteger(config.maxAttempts, "maxAttempts");
  requireNonNegativeInteger(config.retryBackoffMs, "retryBackoffMs");
  requireNonNegativeInteger(config.maxRetryBackoffMs, "maxRetryBackoffMs");
  requirePositiveInteger(config.leaseTtlMs, "leaseTtlMs");
  requirePositiveInteger(config.maxPendingJobs, "maxPendingJobs");
  requirePositiveInteger(
    config.maxPendingJobsPerTenant,
    "maxPendingJobsPerTenant",
  );
  requirePositiveInteger(
    config.finishedJobRetentionMs,
    "finishedJobRetentionMs",
  );

  if (
    typeof config.maxRejectedRatio !== "number" ||
    !Number.isFinite(config.maxRejectedRatio) ||
    config.maxRejectedRatio < 0 ||
    config.maxRejectedRatio > 1
  ) {
    throw new RangeError("maxRejectedRatio must be a number between 0 and 1");
  }
  if (config.maxRetryBackoffMs < config.retryBackoffMs) {
    throw new RangeError("maxRetryBackoffMs must be >= retryBackoffMs");
  }
  if (config.maxPendingJobsPerTenant > config.maxPendingJobs) {
    throw new RangeError("maxPendingJobsPerTenant must be <= maxPendingJobs");
  }
  return config;
}

/**
 * Build a config from `SBOM_*` environment variables.
 *
 * Unset or empty variables keep their defaults; set-but-unparseable values
 * throw so a typo in deployment config is caught at startup.
 */
export function loadSbomIngestionConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): SbomIngestionConfig {
  const overrides: Partial<SbomIngestionConfig> = {};
  for (const [field, envKey] of Object.entries(ENV_KEYS) as [
    keyof SbomIngestionConfig,
    string,
  ][]) {
    const raw = env[envKey];
    if (raw === undefined || raw.trim() === "") {
      continue;
    }
    const value = raw.trim();
    if (field === "enabled") {
      overrides.enabled = parseBoolean(value, envKey);
    } else {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) {
        throw new RangeError(`${envKey} must be a number`);
      }
      (overrides as Record<string, number>)[field] = parsed;
    }
  }
  return resolveSbomIngestionConfig(overrides);
}

function parseBoolean(value: string, envKey: string): boolean {
  const lowered = value.toLowerCase();
  if (["true", "1", "yes", "on"].includes(lowered)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(lowered)) {
    return false;
  }
  throw new RangeError(`${envKey} must be a boolean`);
}

function stripUndefined<T extends object>(value: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== undefined),
  ) as Partial<T>;
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(`${field} must be a positive integer`);
  }
}

function requireNonNegativeInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative integer`);
  }
}
