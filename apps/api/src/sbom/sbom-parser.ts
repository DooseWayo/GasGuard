/**
 * SBOM parsing and normalization.
 *
 * Accepts CycloneDX JSON (1.4-1.6) and SPDX JSON (2.2-2.3) and produces a
 * `NormalizedSbom`. Parsing is pure and deterministic: the same bytes and config
 * always yield the same output, so two workers that race on a job write
 * identical results.
 *
 * Resource use is bounded before any per-component work happens: the byte size
 * is checked before `JSON.parse`, and traversal stops as soon as the component
 * count exceeds `maxComponents`. Traversal of nested CycloneDX components is
 * iterative, so hostile nesting cannot exhaust the call stack.
 *
 * Errors never include document content; `JSON.parse` messages (which can quote
 * fragments of the input) are discarded.
 */

import * as crypto from "crypto";
import { SbomIngestionConfig } from "./sbom-config";
import {
  NormalizedSbom,
  SbomComponent,
  SbomComponentHash,
  SbomFormat,
  SbomIngestionError,
  SbomRejectedComponent,
  SbomRejectionReason,
  SbomSummary,
} from "./sbom-types";

export const SUPPORTED_CYCLONEDX_VERSIONS: readonly string[] = [
  "1.4",
  "1.5",
  "1.6",
];
export const SUPPORTED_SPDX_VERSIONS: readonly string[] = [
  "SPDX-2.2",
  "SPDX-2.3",
];

type ParserLimits = Pick<
  SbomIngestionConfig,
  | "maxDocumentBytes"
  | "maxComponents"
  | "maxNestingDepth"
  | "maxRejectedRatio"
  | "maxReportedRejections"
>;

const MAX_NAME_LENGTH = 512;
const MAX_VERSION_LENGTH = 256;
const MAX_PURL_LENGTH = 2048;
const MAX_LICENSE_LENGTH = 512;

const PURL_PATTERN = /^pkg:([a-zA-Z][a-zA-Z0-9.+-]*)\/[^\s]+$/;
const HEX_PATTERN = /^[0-9a-fA-F]+$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
/**
 * `scheme://user:pass@` in plain or percent-encoded form (purl qualifiers such
 * as `repository_url` are percent-encoded). The userinfo segment may not cross
 * a path separator, so `@` later in a path is left alone.
 */
const URL_USERINFO = /(:\/\/|%3A%2F%2F)(?:(?!%2F)[^/\s@?#&])+?(@|%40)/gi;

const SPDX_NO_VALUE = new Set(["NOASSERTION", "NONE"]);

const HASH_ALGORITHM_ALIASES: Record<string, string> = {
  MD5: "MD5",
  SHA1: "SHA-1",
  "SHA-1": "SHA-1",
  SHA256: "SHA-256",
  "SHA-256": "SHA-256",
  SHA384: "SHA-384",
  "SHA-384": "SHA-384",
  SHA512: "SHA-512",
  "SHA-512": "SHA-512",
  "SHA3-256": "SHA3-256",
  "SHA3-384": "SHA3-384",
  "SHA3-512": "SHA3-512",
  "BLAKE2B-256": "BLAKE2B-256",
  "BLAKE2B-384": "BLAKE2B-384",
  "BLAKE2B-512": "BLAKE2B-512",
  BLAKE3: "BLAKE3",
};

/** SHA-256 of the document's UTF-8 bytes, hex encoded. */
export function computeSbomContentHash(input: string | Buffer): string {
  return crypto.createHash("sha256").update(toBuffer(input)).digest("hex");
}

/** Byte length of the document as it will be hashed and parsed. */
export function sbomByteLength(input: string | Buffer): number {
  return typeof input === "string"
    ? Buffer.byteLength(input, "utf8")
    : input.length;
}

/**
 * Parse and normalize an SBOM document.
 *
 * @throws SbomIngestionError for oversized, malformed, unsupported, or
 *   too-invalid documents. Individually invalid components are reported in
 *   `rejected` instead of failing the whole document, up to `maxRejectedRatio`.
 */
export function parseSbom(
  input: string | Buffer,
  limits: ParserLimits,
): NormalizedSbom {
  if (typeof input !== "string" && !Buffer.isBuffer(input)) {
    throw new SbomIngestionError(
      "INVALID_DOCUMENT",
      "SBOM document must be a string or Buffer",
    );
  }
  if (sbomByteLength(input) > limits.maxDocumentBytes) {
    throw new SbomIngestionError(
      "DOCUMENT_TOO_LARGE",
      `SBOM document exceeds ${limits.maxDocumentBytes} bytes`,
    );
  }

  const contentHash = computeSbomContentHash(input);
  const text = stripBom(
    typeof input === "string" ? input : input.toString("utf8"),
  ).trim();
  if (text === "") {
    throw new SbomIngestionError("INVALID_DOCUMENT", "SBOM document is empty");
  }
  if (text.startsWith("<")) {
    throw new SbomIngestionError(
      "UNSUPPORTED_FORMAT",
      "XML SBOMs are not supported; submit CycloneDX JSON or SPDX JSON",
    );
  }
  if (/^SPDXVersion\s*:/.test(text)) {
    throw new SbomIngestionError(
      "UNSUPPORTED_FORMAT",
      "SPDX tag-value SBOMs are not supported; submit SPDX JSON",
    );
  }

  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new SbomIngestionError(
      "INVALID_DOCUMENT",
      "SBOM document is not valid JSON",
    );
  }
  if (!isPlainObject(doc)) {
    throw new SbomIngestionError(
      "INVALID_DOCUMENT",
      "SBOM document must be a JSON object",
    );
  }

  if (doc.bomFormat === "CycloneDX") {
    const specVersion = requireSupportedVersion(
      doc.specVersion,
      SUPPORTED_CYCLONEDX_VERSIONS,
      "CycloneDX",
    );
    const collected = collectCycloneDx(doc, limits);
    return finalize("cyclonedx", specVersion, contentHash, collected, limits);
  }
  if (
    typeof doc.spdxVersion === "string" &&
    doc.spdxVersion.startsWith("SPDX-")
  ) {
    const specVersion = requireSupportedVersion(
      doc.spdxVersion,
      SUPPORTED_SPDX_VERSIONS,
      "SPDX",
    );
    const collected = collectSpdx(doc, limits);
    return finalize("spdx", specVersion, contentHash, collected, limits);
  }
  throw new SbomIngestionError(
    "UNSUPPORTED_FORMAT",
    "Document is neither CycloneDX JSON nor SPDX JSON",
  );
}

/** Aggregate view of a normalized SBOM for scan reports. */
export function summarizeSbom(
  components: readonly SbomComponent[],
): SbomSummary {
  const byEcosystem: Record<string, number> = {};
  const licenses = new Set<string>();
  let withoutVersion = 0;
  let withoutLicense = 0;
  for (const component of components) {
    const ecosystem = component.ecosystem ?? "unknown";
    byEcosystem[ecosystem] = (byEcosystem[ecosystem] ?? 0) + 1;
    if (!component.version) {
      withoutVersion++;
    }
    if (component.licenses.length === 0) {
      withoutLicense++;
    }
    component.licenses.forEach((license) => licenses.add(license));
  }
  return {
    totalComponents: components.length,
    byEcosystem: sortRecord(byEcosystem),
    componentsWithoutVersion: withoutVersion,
    componentsWithoutLicense: withoutLicense,
    distinctLicenses: [...licenses].sort(compareStrings),
  };
}

interface Collected {
  /** Valid components in document order, before de-duplication. */
  components: SbomComponent[];
  rejected: SbomRejectedComponent[];
  rejectedCount: number;
  total: number;
}

type ComponentResult = SbomComponent | SbomRejectionReason;

function collectCycloneDx(
  doc: Record<string, unknown>,
  limits: ParserLimits,
): Collected {
  const collected = emptyCollected();
  const root = doc.components;
  if (root === undefined) {
    return collected;
  }
  if (!Array.isArray(root)) {
    throw new SbomIngestionError(
      "INVALID_DOCUMENT",
      "CycloneDX `components` must be an array",
    );
  }

  // Depth-first, document order, without recursion.
  const stack: { items: unknown[]; next: number; depth: number }[] = [
    { items: root, next: 0, depth: 1 },
  ];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (frame.next >= frame.items.length) {
      stack.pop();
      continue;
    }
    const entry = frame.items[frame.next++];
    const index = countEntry(collected, limits);

    if (frame.depth > limits.maxNestingDepth) {
      reject(collected, index, "NESTING_TOO_DEEP", limits);
      continue;
    }
    record(collected, index, normalizeCycloneDxComponent(entry), limits);

    if (
      isPlainObject(entry) &&
      Array.isArray(entry.components) &&
      entry.components.length > 0
    ) {
      stack.push({ items: entry.components, next: 0, depth: frame.depth + 1 });
    }
  }
  return collected;
}

function collectSpdx(
  doc: Record<string, unknown>,
  limits: ParserLimits,
): Collected {
  const collected = emptyCollected();
  const packages = doc.packages;
  if (packages === undefined) {
    return collected;
  }
  if (!Array.isArray(packages)) {
    throw new SbomIngestionError(
      "INVALID_DOCUMENT",
      "SPDX `packages` must be an array",
    );
  }

  // The package the document describes is the scanned repository itself, the
  // SPDX counterpart of CycloneDX `metadata.component`; it is not a dependency.
  const described = describedSpdxIds(doc);
  for (const entry of packages) {
    if (
      isPlainObject(entry) &&
      typeof entry.SPDXID === "string" &&
      described.has(entry.SPDXID)
    ) {
      continue;
    }
    const index = countEntry(collected, limits);
    record(collected, index, normalizeSpdxPackage(entry), limits);
  }
  return collected;
}

function normalizeCycloneDxComponent(entry: unknown): ComponentResult {
  if (!isPlainObject(entry)) {
    return "NOT_AN_OBJECT";
  }
  const licenses: string[] = [];
  if (Array.isArray(entry.licenses)) {
    for (const choice of entry.licenses) {
      if (!isPlainObject(choice)) {
        continue;
      }
      if (typeof choice.expression === "string") {
        licenses.push(choice.expression);
      } else if (isPlainObject(choice.license)) {
        const id = choice.license.id ?? choice.license.name;
        if (typeof id === "string") {
          licenses.push(id);
        }
      }
    }
  }
  const hashes: SbomComponentHash[] = [];
  if (Array.isArray(entry.hashes)) {
    for (const hash of entry.hashes) {
      if (isPlainObject(hash)) {
        pushHash(hashes, hash.alg, hash.content);
      }
    }
  }
  return buildComponent({
    name: entry.name,
    version: entry.version,
    group: entry.group,
    purl: entry.purl,
    licenses,
    hashes,
  });
}

function normalizeSpdxPackage(entry: unknown): ComponentResult {
  if (!isPlainObject(entry)) {
    return "NOT_AN_OBJECT";
  }
  let purl: unknown;
  if (Array.isArray(entry.externalRefs)) {
    const ref = entry.externalRefs.find(
      (r) => isPlainObject(r) && r.referenceType === "purl",
    ) as Record<string, unknown> | undefined;
    purl = ref?.referenceLocator;
  }
  const licenses: string[] = [];
  for (const field of [entry.licenseConcluded, entry.licenseDeclared]) {
    if (typeof field === "string" && !SPDX_NO_VALUE.has(field.trim())) {
      licenses.push(field);
    }
  }
  const hashes: SbomComponentHash[] = [];
  if (Array.isArray(entry.checksums)) {
    for (const checksum of entry.checksums) {
      if (isPlainObject(checksum)) {
        pushHash(hashes, checksum.algorithm, checksum.checksumValue);
      }
    }
  }
  const version =
    typeof entry.versionInfo === "string" &&
    SPDX_NO_VALUE.has(entry.versionInfo.trim())
      ? undefined
      : entry.versionInfo;
  return buildComponent({ name: entry.name, version, purl, licenses, hashes });
}

function buildComponent(raw: {
  name: unknown;
  version: unknown;
  group?: unknown;
  purl: unknown;
  licenses: string[];
  hashes: SbomComponentHash[];
}): ComponentResult {
  if (typeof raw.name !== "string" || raw.name.trim() === "") {
    return "MISSING_NAME";
  }
  const name = raw.name.trim();
  if (name.length > MAX_NAME_LENGTH) {
    return "FIELD_TOO_LONG";
  }
  if (CONTROL_CHARS.test(name)) {
    return "INVALID_NAME";
  }

  const component: SbomComponent = { name, licenses: [], hashes: [] };

  if (raw.version !== undefined && raw.version !== null && raw.version !== "") {
    if (
      typeof raw.version !== "string" ||
      raw.version.length > MAX_VERSION_LENGTH ||
      CONTROL_CHARS.test(raw.version)
    ) {
      return "INVALID_VERSION";
    }
    component.version = raw.version.trim();
  }

  if (typeof raw.group === "string" && raw.group.trim() !== "") {
    if (raw.group.length > MAX_NAME_LENGTH) {
      return "FIELD_TOO_LONG";
    }
    component.group = raw.group.trim();
  }

  if (raw.purl !== undefined && raw.purl !== null && raw.purl !== "") {
    if (typeof raw.purl !== "string" || raw.purl.length > MAX_PURL_LENGTH) {
      return "INVALID_PURL";
    }
    const match = PURL_PATTERN.exec(raw.purl.trim());
    if (!match) {
      return "INVALID_PURL";
    }
    component.purl = stripUrlCredentials(raw.purl.trim());
    component.ecosystem = match[1].toLowerCase();
  }

  component.licenses = uniqueSorted(
    raw.licenses
      .map((license) => license.trim())
      .filter(
        (license) => license !== "" && license.length <= MAX_LICENSE_LENGTH,
      ),
  );
  component.hashes = dedupeHashes(raw.hashes);
  return component;
}

function finalize(
  format: SbomFormat,
  specVersion: string,
  contentHash: string,
  collected: Collected,
  limits: ParserLimits,
): NormalizedSbom {
  if (
    collected.total > 0 &&
    collected.rejectedCount / collected.total > limits.maxRejectedRatio
  ) {
    throw new SbomIngestionError(
      "TOO_MANY_INVALID_COMPONENTS",
      `${collected.rejectedCount} of ${collected.total} components are invalid ` +
        `(limit ${Math.round(limits.maxRejectedRatio * 100)}%)`,
    );
  }

  const byIdentity = new Map<string, SbomComponent>();
  for (const component of collected.components) {
    const key = componentIdentity(component);
    if (!byIdentity.has(key)) {
      byIdentity.set(key, component);
    }
  }
  const components = [...byIdentity.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, component]) => component);

  return {
    format,
    specVersion,
    contentHash,
    components,
    stats: {
      total: collected.total,
      accepted: components.length,
      rejected: collected.rejectedCount,
      duplicates: collected.components.length - components.length,
    },
    rejected: collected.rejected,
    summary: summarizeSbom(components),
  };
}

function emptyCollected(): Collected {
  return { components: [], rejected: [], rejectedCount: 0, total: 0 };
}

/** Count one entry and fail as soon as the document exceeds `maxComponents`. */
function countEntry(collected: Collected, limits: ParserLimits): number {
  const index = collected.total++;
  if (collected.total > limits.maxComponents) {
    throw new SbomIngestionError(
      "TOO_MANY_COMPONENTS",
      `SBOM document has more than ${limits.maxComponents} components`,
    );
  }
  return index;
}

function record(
  collected: Collected,
  index: number,
  result: ComponentResult,
  limits: ParserLimits,
): void {
  if (typeof result === "string") {
    reject(collected, index, result, limits);
  } else {
    collected.components.push(result);
  }
}

function reject(
  collected: Collected,
  index: number,
  reason: SbomRejectionReason,
  limits: ParserLimits,
): void {
  collected.rejectedCount++;
  if (collected.rejected.length < limits.maxReportedRejections) {
    collected.rejected.push({ index, reason });
  }
}

function requireSupportedVersion(
  version: unknown,
  supported: readonly string[],
  label: string,
): string {
  if (typeof version !== "string" || !supported.includes(version)) {
    throw new SbomIngestionError(
      "UNSUPPORTED_VERSION",
      `${label} version is not supported; supported versions: ${supported.join(", ")}`,
    );
  }
  return version;
}

function describedSpdxIds(doc: Record<string, unknown>): Set<string> {
  const ids = new Set<string>();
  if (Array.isArray(doc.documentDescribes)) {
    doc.documentDescribes.forEach(
      (id) => typeof id === "string" && ids.add(id),
    );
  }
  if (Array.isArray(doc.relationships)) {
    for (const rel of doc.relationships) {
      if (
        isPlainObject(rel) &&
        rel.spdxElementId === "SPDXRef-DOCUMENT" &&
        rel.relationshipType === "DESCRIBES" &&
        typeof rel.relatedSpdxElement === "string"
      ) {
        ids.add(rel.relatedSpdxElement);
      }
    }
  }
  return ids;
}

function pushHash(
  hashes: SbomComponentHash[],
  algorithm: unknown,
  value: unknown,
): void {
  if (typeof algorithm !== "string" || typeof value !== "string") {
    return;
  }
  const normalizedAlgorithm =
    HASH_ALGORITHM_ALIASES[algorithm.trim().toUpperCase()];
  const normalizedValue = value.trim().toLowerCase();
  if (
    !normalizedAlgorithm ||
    normalizedValue.length > 256 ||
    !HEX_PATTERN.test(normalizedValue)
  ) {
    return;
  }
  hashes.push({ algorithm: normalizedAlgorithm, value: normalizedValue });
}

function dedupeHashes(hashes: SbomComponentHash[]): SbomComponentHash[] {
  const seen = new Map<string, SbomComponentHash>();
  for (const hash of hashes) {
    seen.set(`${hash.algorithm}:${hash.value}`, hash);
  }
  return [...seen.entries()]
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([, hash]) => hash);
}

function componentIdentity(component: SbomComponent): string {
  if (component.purl) {
    return component.purl;
  }
  const group = component.group ? `${component.group}/` : "";
  return `${group}${component.name}@${component.version ?? ""}`;
}

export function stripUrlCredentials(value: string): string {
  return value.replace(URL_USERINFO, "$1");
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort(compareStrings);
}

function sortRecord(record: Record<string, number>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(record).sort(([a], [b]) => compareStrings(a, b)),
  );
}

/** Code-unit comparison: locale-independent, so ordering is reproducible. */
function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function toBuffer(input: string | Buffer): Buffer {
  return typeof input === "string" ? Buffer.from(input, "utf8") : input;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
