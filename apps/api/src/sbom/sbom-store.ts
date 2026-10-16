/**
 * Persistence boundary for ingested SBOMs.
 *
 * Records are keyed by `(tenantId, repositoryId, scanId)`. Every read and write
 * takes the tenant id explicitly, and implementations must never resolve a key
 * across tenants, so one tenant cannot read or overwrite another's SBOM even
 * when repository or scan ids collide.
 *
 * Writes are conditional on `revision`: a record is only replaced by one with
 * an equal or higher revision. The job queue assigns revisions in submission
 * order, so a stalled worker that finishes late can never overwrite the result
 * of a newer submission for the same scan. Equal revisions are accepted because
 * parsing is deterministic and a retried job rewrites identical content.
 */

import * as crypto from "crypto";
import { promises as fs } from "fs";
import * as path from "path";
import { NormalizedSbom, SbomIngestionError } from "./sbom-types";

export interface StoredSbom {
  tenantId: string;
  repositoryId: string;
  scanId: string;
  jobId: string;
  /** Monotonic per-queue sequence of the submission that produced this record. */
  revision: number;
  ingestedAt: number;
  sbom: NormalizedSbom;
}

export type SbomStoreWriteResult = "written" | "stale";

export interface SbomStore {
  /** Upsert `record` unless a record with a higher revision already exists. */
  put(record: StoredSbom): Promise<SbomStoreWriteResult>;
  get(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<StoredSbom | undefined>;
  delete(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<boolean>;
}

export class InMemorySbomStore implements SbomStore {
  private readonly records: Map<string, string> = new Map();

  async put(record: StoredSbom): Promise<SbomStoreWriteResult> {
    const key = recordKey(record.tenantId, record.repositoryId, record.scanId);
    const existing = this.records.get(key);
    if (
      existing &&
      (JSON.parse(existing) as StoredSbom).revision > record.revision
    ) {
      return "stale";
    }
    // Stored serialized so callers can never mutate persisted state by reference.
    this.records.set(key, JSON.stringify(record));
    return "written";
  }

  async get(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<StoredSbom | undefined> {
    const raw = this.records.get(recordKey(tenantId, repositoryId, scanId));
    return raw === undefined ? undefined : (JSON.parse(raw) as StoredSbom);
  }

  async delete(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<boolean> {
    return this.records.delete(recordKey(tenantId, repositoryId, scanId));
  }

  size(): number {
    return this.records.size;
  }
}

/**
 * Durable store writing one JSON file per scan under `rootDir`.
 *
 * Paths are derived from SHA-256 digests of the identifiers, never from the
 * identifiers themselves, so crafted ids cannot traverse outside `rootDir`, and
 * each tenant gets its own directory. Files are written to a temporary name and
 * renamed into place, so a crash mid-write leaves either the old record or the
 * new one, never a torn file.
 *
 * Conditional writes are serialized per key within this process. Deployments
 * that run several API processes against shared storage should use a database
 * store that performs the revision check as a single conditional update.
 */
export class FileSbomStore implements SbomStore {
  private readonly rootDir: string;
  private readonly locks: Map<string, Promise<unknown>> = new Map();

  constructor(rootDir: string) {
    if (typeof rootDir !== "string" || rootDir.trim() === "") {
      throw new TypeError("rootDir must be a non-empty string");
    }
    this.rootDir = path.resolve(rootDir);
  }

  put(record: StoredSbom): Promise<SbomStoreWriteResult> {
    const file = this.filePath(
      record.tenantId,
      record.repositoryId,
      record.scanId,
    );
    return this.withLock(file, async () => {
      const existing = await this.readFile(
        file,
        record.tenantId,
        record.repositoryId,
        record.scanId,
      );
      if (existing && existing.revision > record.revision) {
        return "stale";
      }
      await fs.mkdir(path.dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
      try {
        await fs.writeFile(tmp, JSON.stringify(record), {
          encoding: "utf8",
          mode: 0o600,
        });
        await fs.rename(tmp, file);
      } catch {
        await fs.rm(tmp, { force: true }).catch(() => undefined);
        throw new SbomIngestionError(
          "STORAGE_FAILURE",
          "Failed to persist SBOM record",
        );
      }
      return "written";
    });
  }

  get(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<StoredSbom | undefined> {
    const file = this.filePath(tenantId, repositoryId, scanId);
    return this.readFile(file, tenantId, repositoryId, scanId);
  }

  delete(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<boolean> {
    const file = this.filePath(tenantId, repositoryId, scanId);
    return this.withLock(file, async () => {
      try {
        await fs.unlink(file);
        return true;
      } catch (error) {
        if (isNotFound(error)) {
          return false;
        }
        throw new SbomIngestionError(
          "STORAGE_FAILURE",
          "Failed to delete SBOM record",
        );
      }
    });
  }

  private async readFile(
    file: string,
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): Promise<StoredSbom | undefined> {
    let raw: string;
    try {
      raw = await fs.readFile(file, "utf8");
    } catch (error) {
      if (isNotFound(error)) {
        return undefined;
      }
      throw new SbomIngestionError(
        "STORAGE_FAILURE",
        "Failed to read SBOM record",
      );
    }
    let record: StoredSbom;
    try {
      record = JSON.parse(raw) as StoredSbom;
    } catch {
      throw new SbomIngestionError(
        "STORAGE_FAILURE",
        "Stored SBOM record is corrupt",
      );
    }
    // Defence in depth: the digest path must hold the record it was asked for.
    if (
      record.tenantId !== tenantId ||
      record.repositoryId !== repositoryId ||
      record.scanId !== scanId
    ) {
      throw new SbomIngestionError(
        "STORAGE_FAILURE",
        "Stored SBOM record does not match its key",
      );
    }
    return record;
  }

  private filePath(
    tenantId: string,
    repositoryId: string,
    scanId: string,
  ): string {
    return path.join(
      this.rootDir,
      digest(tenantId),
      `${digest(`${repositoryId}\u0000${scanId}`)}.json`,
    );
  }

  private withLock<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.then(task, task);
    const settled = run.catch(() => undefined);
    this.locks.set(key, settled);
    void settled.then(() => {
      if (this.locks.get(key) === settled) {
        this.locks.delete(key);
      }
    });
    return run;
  }
}

function recordKey(
  tenantId: string,
  repositoryId: string,
  scanId: string,
): string {
  return `${tenantId}\u0000${repositoryId}\u0000${scanId}`;
}

function digest(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function isNotFound(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === "ENOENT";
}
