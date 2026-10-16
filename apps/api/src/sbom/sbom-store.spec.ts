import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import {
  FileSbomStore,
  InMemorySbomStore,
  SbomStore,
  StoredSbom,
} from "./sbom-store";
import { NormalizedSbom } from "./sbom-types";

const sbom: NormalizedSbom = {
  format: "cyclonedx",
  specVersion: "1.5",
  contentHash: "a".repeat(64),
  components: [
    { name: "lodash", version: "4.17.21", licenses: ["MIT"], hashes: [] },
  ],
  stats: { total: 1, accepted: 1, rejected: 0, duplicates: 0 },
  rejected: [],
  summary: {
    totalComponents: 1,
    byEcosystem: { unknown: 1 },
    componentsWithoutVersion: 0,
    componentsWithoutLicense: 0,
    distinctLicenses: ["MIT"],
  },
};

function record(overrides: Partial<StoredSbom> = {}): StoredSbom {
  return {
    tenantId: "tenant-a",
    repositoryId: "org/repo",
    scanId: "scan-1",
    jobId: "sbom_1",
    revision: 1,
    ingestedAt: 1_000,
    sbom: JSON.parse(JSON.stringify(sbom)) as NormalizedSbom,
    ...overrides,
  };
}

const tempDirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "gasguard-sbom-store-"));
  tempDirs.push(dir);
  return dir;
}

afterAll(async () => {
  await Promise.all(
    tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

describe.each([
  [
    "InMemorySbomStore",
    async (): Promise<SbomStore> => new InMemorySbomStore(),
  ],
  [
    "FileSbomStore",
    async (): Promise<SbomStore> => new FileSbomStore(await tempDir()),
  ],
])("%s", (_name, create) => {
  it("round-trips a record", async () => {
    const store = await create();
    expect(await store.put(record())).toBe("written");
    expect(await store.get("tenant-a", "org/repo", "scan-1")).toEqual(record());
  });

  it("returns undefined for a missing record", async () => {
    const store = await create();
    expect(await store.get("tenant-a", "org/repo", "missing")).toBeUndefined();
  });

  it("never resolves a record across tenants", async () => {
    const store = await create();
    await store.put(record({ tenantId: "tenant-a" }));
    expect(await store.get("tenant-b", "org/repo", "scan-1")).toBeUndefined();
    await store.put(
      record({ tenantId: "tenant-b", jobId: "sbom_b", revision: 99 }),
    );
    expect((await store.get("tenant-a", "org/repo", "scan-1"))?.jobId).toBe(
      "sbom_1",
    );
  });

  it("refuses to overwrite a newer revision and accepts equal or newer ones", async () => {
    const store = await create();
    await store.put(record({ revision: 5, jobId: "new" }));
    expect(await store.put(record({ revision: 4, jobId: "old" }))).toBe(
      "stale",
    );
    expect((await store.get("tenant-a", "org/repo", "scan-1"))?.jobId).toBe(
      "new",
    );
    expect(await store.put(record({ revision: 5, jobId: "retry" }))).toBe(
      "written",
    );
    expect(await store.put(record({ revision: 6, jobId: "newer" }))).toBe(
      "written",
    );
  });

  it("deletes records", async () => {
    const store = await create();
    await store.put(record());
    expect(await store.delete("tenant-a", "org/repo", "scan-1")).toBe(true);
    expect(await store.delete("tenant-a", "org/repo", "scan-1")).toBe(false);
    expect(await store.get("tenant-a", "org/repo", "scan-1")).toBeUndefined();
  });

  it("does not let callers mutate stored state by reference", async () => {
    const store = await create();
    const original = record();
    await store.put(original);
    original.sbom.components.push({
      name: "injected",
      licenses: [],
      hashes: [],
    });
    const fetched = await store.get("tenant-a", "org/repo", "scan-1");
    expect(fetched?.sbom.components).toHaveLength(1);
  });
});

describe("FileSbomStore - persistence", () => {
  it("keeps records across store instances (process restart)", async () => {
    const dir = await tempDir();
    await new FileSbomStore(dir).put(record());
    expect(
      await new FileSbomStore(dir).get("tenant-a", "org/repo", "scan-1"),
    ).toEqual(record());
  });

  it("contains crafted identifiers inside rootDir", async () => {
    const dir = await tempDir();
    const store = new FileSbomStore(dir);
    await store.put(
      record({
        tenantId: "../../etc",
        repositoryId: "../passwd",
        scanId: "/root",
      }),
    );
    const files = await listFiles(dir);
    expect(files).toHaveLength(1);
    expect(files[0].startsWith(dir)).toBe(true);
    expect(files[0]).toMatch(/[0-9a-f]{64}[\\/][0-9a-f]{64}\.json$/);
  });

  it("serializes concurrent conditional writes to the same key", async () => {
    const store = new FileSbomStore(await tempDir());
    const revisions = [3, 1, 5, 2, 4];
    await Promise.all(
      revisions.map((revision) =>
        store.put(record({ revision, jobId: `j${revision}` })),
      ),
    );
    expect((await store.get("tenant-a", "org/repo", "scan-1"))?.revision).toBe(
      5,
    );
  });

  it("leaves no temporary files behind", async () => {
    const dir = await tempDir();
    const store = new FileSbomStore(dir);
    await Promise.all(
      [1, 2, 3].map((revision) => store.put(record({ revision }))),
    );
    expect((await listFiles(dir)).filter((f) => f.endsWith(".tmp"))).toEqual(
      [],
    );
  });

  it("reports a corrupt record as a retryable STORAGE_FAILURE", async () => {
    const dir = await tempDir();
    const store = new FileSbomStore(dir);
    await store.put(record());
    const [file] = await listFiles(dir);
    await fs.writeFile(file, "{not json");
    await expect(
      store.get("tenant-a", "org/repo", "scan-1"),
    ).rejects.toMatchObject({
      code: "STORAGE_FAILURE",
      retryable: true,
    });
  });

  it("rejects a record whose contents do not match its key", async () => {
    const dir = await tempDir();
    const store = new FileSbomStore(dir);
    await store.put(record());
    const [file] = await listFiles(dir);
    await fs.writeFile(file, JSON.stringify(record({ tenantId: "tenant-b" })));
    await expect(
      store.get("tenant-a", "org/repo", "scan-1"),
    ).rejects.toMatchObject({
      code: "STORAGE_FAILURE",
    });
  });

  it("requires a root directory", () => {
    expect(() => new FileSbomStore("")).toThrow(TypeError);
  });
});

async function listFiles(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const full = path.join(dir, entry.name);
      return entry.isDirectory() ? listFiles(full) : Promise.resolve([full]);
    }),
  );
  return nested.flat();
}
