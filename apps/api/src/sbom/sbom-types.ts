/**
 * Shared types for SBOM ingestion on repository scans.
 *
 * An uploaded SBOM (CycloneDX or SPDX JSON) is normalized into a single
 * format-independent shape so downstream analyzers and reports never need to
 * know which standard the repository used.
 */

export type SbomFormat = "cyclonedx" | "spdx";

export interface SbomComponentHash {
  /** Upper-case algorithm name, e.g. `SHA-256`. */
  algorithm: string;
  /** Lower-case hexadecimal digest. */
  value: string;
}

export interface SbomComponent {
  name: string;
  version?: string;
  /** CycloneDX `group` / Maven namespace, when present. */
  group?: string;
  /** Package URL with any embedded credentials stripped. */
  purl?: string;
  /** Package ecosystem derived from the purl type (`npm`, `cargo`, ...). */
  ecosystem?: string;
  /** SPDX license identifiers, names, or expressions, sorted and unique. */
  licenses: string[];
  hashes: SbomComponentHash[];
}

export type SbomRejectionReason =
  | "NOT_AN_OBJECT"
  | "MISSING_NAME"
  | "INVALID_NAME"
  | "FIELD_TOO_LONG"
  | "INVALID_VERSION"
  | "INVALID_PURL"
  | "NESTING_TOO_DEEP";

export interface SbomRejectedComponent {
  /** Position of the component in document order (depth-first). */
  index: number;
  reason: SbomRejectionReason;
}

export interface SbomIngestionStats {
  /** Component entries seen in the document, including rejected ones. */
  total: number;
  accepted: number;
  rejected: number;
  /** Valid entries dropped because an identical component was already seen. */
  duplicates: number;
}

export interface SbomSummary {
  totalComponents: number;
  /** Component count per ecosystem; components without a purl count as `unknown`. */
  byEcosystem: Record<string, number>;
  componentsWithoutVersion: number;
  componentsWithoutLicense: number;
  distinctLicenses: string[];
}

export interface NormalizedSbom {
  format: SbomFormat;
  specVersion: string;
  /** SHA-256 of the raw uploaded bytes; identifies the document. */
  contentHash: string;
  /** Components sorted by identity so output is deterministic. */
  components: SbomComponent[];
  stats: SbomIngestionStats;
  /** First `maxReportedRejections` rejections, in document order. */
  rejected: SbomRejectedComponent[];
  summary: SbomSummary;
}

export type SbomErrorCode =
  /** Document exceeds `maxDocumentBytes`. */
  | "DOCUMENT_TOO_LARGE"
  /** Document is empty, not JSON, or structurally invalid. */
  | "INVALID_DOCUMENT"
  /** Document is not CycloneDX JSON or SPDX JSON (e.g. XML, tag-value). */
  | "UNSUPPORTED_FORMAT"
  /** Recognised format but a spec version outside the supported range. */
  | "UNSUPPORTED_VERSION"
  /** More components than `maxComponents`. */
  | "TOO_MANY_COMPONENTS"
  /** Rejected components exceed the configured partial-failure tolerance. */
  | "TOO_MANY_INVALID_COMPONENTS"
  /** Tenant, repository, or scan identifier is missing or malformed. */
  | "INVALID_REQUEST"
  /** SBOM ingestion is switched off by configuration. */
  | "INGESTION_DISABLED"
  /** A different SBOM is already in flight for the same scan. */
  | "CONFLICT"
  /** Global or per-tenant pending-job limit reached; retry later. */
  | "QUEUE_FULL"
  /** Persisting the result failed; the job is retried. */
  | "STORAGE_FAILURE"
  /** The worker's lease expired before it finished; the job is retried. */
  | "LEASE_EXPIRED";

const RETRYABLE_CODES: ReadonlySet<SbomErrorCode> = new Set<SbomErrorCode>([
  "QUEUE_FULL",
  "STORAGE_FAILURE",
  "LEASE_EXPIRED",
]);

/**
 * Error raised by every SBOM ingestion boundary.
 *
 * Messages are fixed, human-readable strings that never echo document content,
 * so the error is always safe to log or return to a client.
 */
export class SbomIngestionError extends Error {
  readonly code: SbomErrorCode;
  readonly retryable: boolean;

  constructor(code: SbomErrorCode, message: string) {
    super(message);
    this.name = "SbomIngestionError";
    this.code = code;
    this.retryable = RETRYABLE_CODES.has(code);
  }
}

export function isRetryableSbomError(code: SbomErrorCode): boolean {
  return RETRYABLE_CODES.has(code);
}
