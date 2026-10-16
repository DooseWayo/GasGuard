import * as fs from "fs";
import * as path from "path";
import {
  DEFAULT_SBOM_INGESTION_CONFIG,
  SbomIngestionConfig,
} from "./sbom-config";
import {
  computeSbomContentHash,
  parseSbom,
  stripUrlCredentials,
} from "./sbom-parser";
import { SbomErrorCode, SbomIngestionError } from "./sbom-types";

const fixture = (name: string) =>
  fs.readFileSync(path.join(__dirname, "__fixtures__", name), "utf8");

const limits = (overrides: Partial<SbomIngestionConfig> = {}) => ({
  ...DEFAULT_SBOM_INGESTION_CONFIG,
  ...overrides,
});

function cyclonedx(components: unknown[], specVersion = "1.5"): string {
  return JSON.stringify({ bomFormat: "CycloneDX", specVersion, components });
}

function expectCode(
  fn: () => unknown,
  code: SbomErrorCode,
): SbomIngestionError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(SbomIngestionError);
    expect((error as SbomIngestionError).code).toBe(code);
    return error as SbomIngestionError;
  }
  throw new Error(`expected ${code} to be thrown`);
}

describe("parseSbom - CycloneDX", () => {
  it("normalizes components, flattens nesting, de-duplicates and sorts", () => {
    const raw = fixture("cyclonedx-1.5.json");
    const sbom = parseSbom(raw, limits({ maxRejectedRatio: 0.25 }));

    expect(sbom.format).toBe("cyclonedx");
    expect(sbom.specVersion).toBe("1.5");
    expect(sbom.contentHash).toBe(computeSbomContentHash(raw));
    expect(sbom.stats).toEqual({
      total: 6,
      accepted: 4,
      rejected: 1,
      duplicates: 1,
    });
    expect(sbom.rejected).toEqual([{ index: 5, reason: "MISSING_NAME" }]);
    expect(sbom.components.map((c) => c.name)).toEqual([
      "ERC20.sol",
      "soroban-sdk",
      "contracts",
      "lodash",
    ]);

    const lodash = sbom.components.find((c) => c.name === "lodash");
    expect(lodash).toEqual({
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21",
      ecosystem: "npm",
      licenses: ["MIT"],
      hashes: [{ algorithm: "SHA-256", value: "abcdef0123456789" }],
    });
    expect(sbom.components.find((c) => c.name === "contracts")?.group).toBe(
      "@openzeppelin",
    );
  });

  it("excludes metadata.component, which is the scanned repository itself", () => {
    const sbom = parseSbom(
      fixture("cyclonedx-1.5.json"),
      limits({ maxRejectedRatio: 0.25 }),
    );
    expect(sbom.components.some((c) => c.name === "gasguard-sample-repo")).toBe(
      false,
    );
  });

  it("strips credentials embedded in purl qualifiers", () => {
    const sbom = parseSbom(
      fixture("cyclonedx-1.5.json"),
      limits({ maxRejectedRatio: 0.25 }),
    );
    const soroban = sbom.components.find((c) => c.name === "soroban-sdk");
    expect(soroban?.purl).toBe(
      "pkg:cargo/soroban-sdk@21.0.0?repository_url=https%3A%2F%2Fcrates.example.com",
    );
    expect(JSON.stringify(sbom)).not.toContain("hunter2");
  });

  it("builds a report summary", () => {
    const sbom = parseSbom(
      fixture("cyclonedx-1.5.json"),
      limits({ maxRejectedRatio: 0.25 }),
    );
    expect(sbom.summary).toEqual({
      totalComponents: 4,
      byEcosystem: { cargo: 1, npm: 2, unknown: 1 },
      componentsWithoutVersion: 0,
      componentsWithoutLicense: 1,
      distinctLicenses: ["Apache-2.0", "MIT"],
    });
  });

  it("is deterministic regardless of component order", () => {
    const a = { name: "a", version: "1", purl: "pkg:npm/a@1" };
    const b = { name: "b", version: "2", purl: "pkg:npm/b@2" };
    const first = parseSbom(cyclonedx([a, b]), limits());
    const second = parseSbom(cyclonedx([b, a]), limits());
    expect(first.components).toEqual(second.components);
  });

  it.each(["1.4", "1.5", "1.6"])("accepts spec version %s", (version) => {
    expect(parseSbom(cyclonedx([], version), limits()).specVersion).toBe(
      version,
    );
  });

  it.each(["1.3", "2.0", undefined])("rejects spec version %s", (version) => {
    const raw = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: version,
    });
    expectCode(() => parseSbom(raw, limits()), "UNSUPPORTED_VERSION");
  });

  it("accepts an SBOM with no components", () => {
    const sbom = parseSbom(
      JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5" }),
      limits(),
    );
    expect(sbom.components).toEqual([]);
    expect(sbom.stats).toEqual({
      total: 0,
      accepted: 0,
      rejected: 0,
      duplicates: 0,
    });
  });

  it("rejects a non-array components field", () => {
    const raw = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: {},
    });
    expectCode(() => parseSbom(raw, limits()), "INVALID_DOCUMENT");
  });

  it("records a reason for each kind of invalid component", () => {
    const raw = cyclonedx([
      "not-an-object",
      { version: "1" },
      { name: "x".repeat(513) },
      { name: "bad\u0007name" },
      { name: "v", version: 42 },
      { name: "p", purl: "not-a-purl" },
    ]);
    const sbom = parseSbom(raw, limits({ maxRejectedRatio: 1 }));
    expect(sbom.rejected.map((r) => r.reason)).toEqual([
      "NOT_AN_OBJECT",
      "MISSING_NAME",
      "FIELD_TOO_LONG",
      "INVALID_NAME",
      "INVALID_VERSION",
      "INVALID_PURL",
    ]);
    expect(sbom.components).toEqual([]);
  });

  it("drops unknown or non-hex hashes without rejecting the component", () => {
    const raw = cyclonedx([
      {
        name: "h",
        hashes: [
          { alg: "CRC32", content: "abcd" },
          { alg: "SHA-1", content: "zz" },
          { alg: "sha-512", content: "AA" },
        ],
      },
    ]);
    expect(parseSbom(raw, limits()).components[0].hashes).toEqual([
      { algorithm: "SHA-512", value: "aa" },
    ]);
  });
});

describe("parseSbom - SPDX", () => {
  it("normalizes packages and skips the described root package", () => {
    const sbom = parseSbom(fixture("spdx-2.3.json"), limits());
    expect(sbom.format).toBe("spdx");
    expect(sbom.specVersion).toBe("SPDX-2.3");
    expect(sbom.stats).toEqual({
      total: 2,
      accepted: 2,
      rejected: 0,
      duplicates: 0,
    });
    expect(sbom.components).toEqual([
      {
        name: "serde",
        purl: "pkg:cargo/serde@1.0.200",
        ecosystem: "cargo",
        licenses: ["MIT OR Apache-2.0"],
        hashes: [],
      },
      {
        name: "ethers",
        version: "6.16.0",
        purl: "pkg:npm/ethers@6.16.0",
        ecosystem: "npm",
        licenses: ["MIT"],
        hashes: [{ algorithm: "SHA-256", value: "00ff00ff" }],
      },
    ]);
  });

  it("rejects SPDX 2.1", () => {
    const raw = JSON.stringify({ spdxVersion: "SPDX-2.1", packages: [] });
    expectCode(() => parseSbom(raw, limits()), "UNSUPPORTED_VERSION");
  });

  it("rejects a non-array packages field", () => {
    const raw = JSON.stringify({ spdxVersion: "SPDX-2.3", packages: "nope" });
    expectCode(() => parseSbom(raw, limits()), "INVALID_DOCUMENT");
  });
});

describe("parseSbom - unsupported and invalid input", () => {
  it.each([
    [
      "CycloneDX XML",
      '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>',
    ],
    ["SPDX tag-value", "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n"],
    ["unknown JSON", JSON.stringify({ hello: "world" })],
  ])("rejects %s as UNSUPPORTED_FORMAT", (_label, raw) => {
    expectCode(() => parseSbom(raw, limits()), "UNSUPPORTED_FORMAT");
  });

  it.each([
    ["empty", ""],
    ["whitespace", "   \n"],
    ["a JSON array", "[]"],
    ["a JSON string", '"cyclonedx"'],
  ])("rejects %s as INVALID_DOCUMENT", (_label, raw) => {
    expectCode(() => parseSbom(raw, limits()), "INVALID_DOCUMENT");
  });

  it("does not echo document content in JSON syntax errors", () => {
    // Assembled at runtime so secret scanners do not flag the test itself.
    const secret = ["ghp", "_", "FAKE".repeat(9)].join("");
    const error = expectCode(
      () => parseSbom(`{"token": ${secret}}`, limits()),
      "INVALID_DOCUMENT",
    );
    expect(error.message).not.toContain(secret);
    expect(error.retryable).toBe(false);
  });

  it("accepts a UTF-8 BOM prefix and Buffer input", () => {
    const raw = Buffer.from(`﻿${cyclonedx([{ name: "a" }])}`, "utf8");
    expect(parseSbom(raw, limits()).components).toHaveLength(1);
  });
});

describe("parseSbom - limits", () => {
  it("accepts a document of exactly maxDocumentBytes and rejects one byte more", () => {
    const raw = cyclonedx([{ name: "a" }]);
    const size = Buffer.byteLength(raw);
    expect(() =>
      parseSbom(raw, limits({ maxDocumentBytes: size })),
    ).not.toThrow();
    expectCode(
      () => parseSbom(raw, limits({ maxDocumentBytes: size - 1 })),
      "DOCUMENT_TOO_LARGE",
    );
  });

  it("measures size in UTF-8 bytes, not characters", () => {
    const raw = cyclonedx([{ name: "é".repeat(10) }]);
    expectCode(
      () => parseSbom(raw, limits({ maxDocumentBytes: raw.length })),
      "DOCUMENT_TOO_LARGE",
    );
  });

  it("accepts exactly maxComponents and rejects one more, counting nested entries", () => {
    const nested = [
      { name: "parent", components: [{ name: "child" }] },
      { name: "sibling" },
    ];
    expect(
      parseSbom(cyclonedx(nested), limits({ maxComponents: 3 })).stats.total,
    ).toBe(3);
    expectCode(
      () => parseSbom(cyclonedx(nested), limits({ maxComponents: 2 })),
      "TOO_MANY_COMPONENTS",
    );
  });

  it("rejects components nested deeper than maxNestingDepth without recursing", () => {
    // Built as text: JSON.stringify itself would overflow on this depth.
    const levels = 5_000;
    let nested = "";
    for (let level = levels; level >= 1; level--) {
      nested = `{"name":"level-${level}"${nested ? `,"components":[${nested}]` : ""}}`;
    }
    const raw = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[${nested}]}`;
    const sbom = parseSbom(
      raw,
      limits({ maxNestingDepth: 3, maxRejectedRatio: 1 }),
    );
    expect(sbom.stats.accepted).toBe(3);
    expect(sbom.rejected).toEqual([{ index: 3, reason: "NESTING_TOO_DEEP" }]);
  });

  it("tolerates rejections up to maxRejectedRatio and fails above it", () => {
    const components = [{ name: "a" }, { name: "b" }, { name: "c" }, {}];
    expect(
      parseSbom(cyclonedx(components), limits({ maxRejectedRatio: 0.25 })).stats
        .rejected,
    ).toBe(1);
    expectCode(
      () => parseSbom(cyclonedx(components), limits({ maxRejectedRatio: 0.2 })),
      "TOO_MANY_INVALID_COMPONENTS",
    );
  });

  it("treats any rejection as fatal when maxRejectedRatio is 0", () => {
    expectCode(
      () =>
        parseSbom(
          cyclonedx([{ name: "a" }, {}]),
          limits({ maxRejectedRatio: 0 }),
        ),
      "TOO_MANY_INVALID_COMPONENTS",
    );
  });

  it("caps rejection details at maxReportedRejections while keeping exact counts", () => {
    const components = Array.from({ length: 10 }, () => ({}));
    const sbom = parseSbom(
      cyclonedx(components),
      limits({ maxRejectedRatio: 1, maxReportedRejections: 3 }),
    );
    expect(sbom.stats.rejected).toBe(10);
    expect(sbom.rejected).toHaveLength(3);
  });
});

describe("stripUrlCredentials", () => {
  it.each([
    ["https://user:pass@host/path", "https://host/path"],
    ["https%3A%2F%2Fuser%3Apass%40host", "https%3A%2F%2Fhost"],
    ["https://host/path@v1", "https://host/path@v1"],
    ["https%3A%2F%2Fhost%2Fpath%40v1", "https%3A%2F%2Fhost%2Fpath%40v1"],
    ["pkg:npm/%40scope/name@1.0.0", "pkg:npm/%40scope/name@1.0.0"],
  ])("%s -> %s", (input, expected) => {
    expect(stripUrlCredentials(input)).toBe(expected);
  });
});
