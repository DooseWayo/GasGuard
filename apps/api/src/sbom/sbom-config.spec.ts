import {
  DEFAULT_SBOM_INGESTION_CONFIG,
  loadSbomIngestionConfigFromEnv,
  resolveSbomIngestionConfig,
} from "./sbom-config";

describe("resolveSbomIngestionConfig", () => {
  it("returns the defaults when given no overrides", () => {
    expect(resolveSbomIngestionConfig()).toEqual(DEFAULT_SBOM_INGESTION_CONFIG);
  });

  it("merges overrides and ignores undefined values", () => {
    const config = resolveSbomIngestionConfig({
      maxComponents: 10,
      maxAttempts: undefined,
    });
    expect(config.maxComponents).toBe(10);
    expect(config.maxAttempts).toBe(DEFAULT_SBOM_INGESTION_CONFIG.maxAttempts);
  });

  it.each([
    ["maxDocumentBytes", 0],
    ["maxComponents", -1],
    ["maxNestingDepth", 1.5],
    ["maxAttempts", 0],
    ["leaseTtlMs", 0],
    ["maxPendingJobs", 0],
    ["finishedJobRetentionMs", 0],
    ["retryBackoffMs", -1],
    ["maxReportedRejections", -1],
  ])("rejects invalid %s=%s", (field, value) => {
    expect(() => resolveSbomIngestionConfig({ [field]: value })).toThrow(
      new RegExp(field),
    );
  });

  it.each([-0.1, 1.1, Number.NaN])("rejects maxRejectedRatio=%s", (value) => {
    expect(() =>
      resolveSbomIngestionConfig({ maxRejectedRatio: value }),
    ).toThrow(/maxRejectedRatio/);
  });

  it("accepts the maxRejectedRatio boundaries 0 and 1", () => {
    expect(
      resolveSbomIngestionConfig({ maxRejectedRatio: 0 }).maxRejectedRatio,
    ).toBe(0);
    expect(
      resolveSbomIngestionConfig({ maxRejectedRatio: 1 }).maxRejectedRatio,
    ).toBe(1);
  });

  it("rejects inconsistent backoff and capacity settings", () => {
    expect(() =>
      resolveSbomIngestionConfig({ retryBackoffMs: 10, maxRetryBackoffMs: 5 }),
    ).toThrow(/maxRetryBackoffMs/);
    expect(() =>
      resolveSbomIngestionConfig({
        maxPendingJobs: 5,
        maxPendingJobsPerTenant: 6,
      }),
    ).toThrow(/maxPendingJobsPerTenant/);
  });
});

describe("loadSbomIngestionConfigFromEnv", () => {
  it("uses defaults for unset and empty variables", () => {
    expect(loadSbomIngestionConfigFromEnv({ SBOM_MAX_COMPONENTS: "" })).toEqual(
      DEFAULT_SBOM_INGESTION_CONFIG,
    );
  });

  it("parses numbers and booleans", () => {
    const config = loadSbomIngestionConfigFromEnv({
      SBOM_INGESTION_ENABLED: "off",
      SBOM_MAX_DOCUMENT_BYTES: "2048",
      SBOM_MAX_REJECTED_RATIO: "0.5",
      SBOM_LEASE_TTL_MS: " 30000 ",
    });
    expect(config.enabled).toBe(false);
    expect(config.maxDocumentBytes).toBe(2048);
    expect(config.maxRejectedRatio).toBe(0.5);
    expect(config.leaseTtlMs).toBe(30_000);
  });

  it("fails fast on unparseable values", () => {
    expect(() =>
      loadSbomIngestionConfigFromEnv({ SBOM_MAX_ATTEMPTS: "three" }),
    ).toThrow(/SBOM_MAX_ATTEMPTS/);
    expect(() =>
      loadSbomIngestionConfigFromEnv({ SBOM_INGESTION_ENABLED: "maybe" }),
    ).toThrow(/SBOM_INGESTION_ENABLED/);
    expect(() =>
      loadSbomIngestionConfigFromEnv({ SBOM_MAX_ATTEMPTS: "0" }),
    ).toThrow(/maxAttempts/);
  });
});
