/**
 * Persistence tests against a fake IndexedDB (`fake-indexeddb`), so the real
 * request/transaction code paths run rather than a mock of them.
 */
import { describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { clearAll, getBlob, loadSnapshot, putBlob, saveSnapshot, storageAvailable } from "../src/lib/db";
import { blobStorageSupported } from "../vitest.setup";

describe("persistence", () => {
  it("reports storage availability", () => {
    expect(storageAvailable()).toBe(true);
  });

  it("round-trips a snapshot", async () => {
    await saveSnapshot({
      titles: [
        {
          id: "t1",
          kind: "movie",
          name: "Arrival",
          tags: [],
          addedAt: "2024-01-01T00:00:00.000Z",
          progress: 0,
          watched: false,
          files: [],
        },
      ],
      progress: {},
      collections: { Faves: ["t1"] },
    });
    const loaded = await loadSnapshot();
    expect(loaded?.titles[0]?.name).toBe("Arrival");
    expect(loaded?.collections.Faves).toEqual(["t1"]);
  });

  it.skipIf(!blobStorageSupported)("stores and returns media blobs by id", async () => {
    const blob = new Blob([new Uint8Array([1, 2, 3])], { type: "video/mp4" });
    await putBlob({ id: "f1", blob, fileName: "a.mp4" });
    const loaded = await getBlob("f1");
    expect(loaded?.fileName).toBe("a.mp4");
    expect(loaded?.blob.size).toBe(3);
  });

  it("returns undefined for an unknown id", async () => {
    expect(await getBlob("nope")).toBeUndefined();
  });

  it("clears everything", async () => {
    await saveSnapshot({ titles: [], progress: {}, collections: {} });
    await putBlob({ id: "f2", blob: new Blob(["x"]), fileName: "b.mp4" });
    await clearAll();
    expect(await loadSnapshot()).toBeUndefined();
    expect(await getBlob("f2")).toBeUndefined();
  });
});
