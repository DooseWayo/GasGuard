import { SbomIngestionMetrics, sanitizeLogFields } from "./sbom-metrics";

describe("SbomIngestionMetrics", () => {
  it("counts submissions, failures, and component totals", () => {
    const metrics = new SbomIngestionMetrics();
    metrics.recordSubmission("accepted");
    metrics.recordSubmission("rejected", "QUEUE_FULL");
    metrics.recordCompleted(20, 5, 1);
    metrics.recordFailure("STORAGE_FAILURE", "retry_scheduled", 10);
    metrics.recordFailure("UNSUPPORTED_FORMAT", "dead_lettered", 2);
    metrics.recordStale();
    metrics.recordLeasesRecovered(2);

    expect(metrics.snapshot()).toEqual({
      submissions: { accepted: 1, rejected: 1 },
      submissionRejections: { QUEUE_FULL: 1 },
      jobsCompleted: 1,
      jobFailures: { STORAGE_FAILURE: 1, UNSUPPORTED_FORMAT: 1 },
      jobsRetried: 1,
      jobsDeadLettered: 1,
      staleCompletions: 1,
      leasesRecovered: 2,
      componentsIngested: 5,
      componentsRejected: 1,
      ingestDurationMs: { count: 3, sum: 32, max: 20 },
    });
  });

  it("renders Prometheus text with closed-set labels and queue gauges", () => {
    const metrics = new SbomIngestionMetrics();
    metrics.recordSubmission("accepted");
    const text = metrics.toPrometheus({ pending: 3 });
    expect(text).toContain(
      'gasguard_sbom_submissions_total{outcome="accepted"} 1',
    );
    expect(text).toContain('gasguard_sbom_queue_jobs{status="pending"} 3');
    expect(text.endsWith("\n")).toBe(true);
  });
});

describe("sanitizeLogFields", () => {
  it("keeps primitives and drops payload- or credential-like keys", () => {
    expect(
      sanitizeLogFields({
        jobId: "sbom_1",
        components: 4,
        superseded: false,
        contentHash: "abc123",
        payload: "{...}",
        document: "{...}",
        apiKey: "k",
        authorization: "Bearer x",
        nested: { secret: 1 },
      }),
    ).toEqual({
      jobId: "sbom_1",
      components: 4,
      superseded: false,
      contentHash: "abc123",
    });
  });

  it("truncates long strings", () => {
    const value = sanitizeLogFields({ scanId: "x".repeat(500) })
      .scanId as string;
    expect(value.length).toBe(201);
  });
});
