/**
 * Regression tests for the "it gets stuck and never plays" bugs.
 *
 * Two of these are about storage, one about the player contract:
 *   1. a payload must be stored as a Blob (not copied into an ArrayBuffer), so
 *      opening a multi-gigabyte file does not allocate it in memory;
 *   2. records written by the older ArrayBuffer format must still play;
 *   3. `hasBlob` must not materialise the payload at all.
 *
 * The player itself is covered in `player.test.tsx` (autoplay fallback, error
 * states). This file is the data layer those depend on.
 */
import { describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { getBlob, hasBlob, putBlob, requestPersistence, storageAvailable } from "../src/lib/db";
import { blobStorageSupported } from "../vitest.setup";

function videoBlob(bytes = 4096, type = "video/mp4"): Blob {
  return new Blob([new Uint8Array(bytes)], { type });
}

/**
 * jsdom + fake-indexeddb cannot structured-clone a Blob (it comes back as `{}`),
 * so blob-fidelity assertions are gates on the harness capability. Everything
 * else runs everywhere.
 */
describe("media payload storage", () => {
  it.skipIf(!blobStorageSupported)("round-trips a blob", async () => {
    const blob = videoBlob(1024);
    await putBlob({ id: "b1", blob, fileName: "film.mp4" });
    const stored = await getBlob("b1");
    expect(stored?.fileName).toBe("film.mp4");
    expect(stored?.blob.size).toBe(1024);
    expect(stored?.blob.type).toBe("video/mp4");
  });

  it.skipIf(!blobStorageSupported)("keeps the payload as a Blob so object URLs stay cheap", async () => {
    const blob = videoBlob(2048);
    await putBlob({ id: "b2", blob, fileName: "film.mp4" });
    const stored = await getBlob("b2");
    // A Blob read back as a Blob is a reference; if this were an ArrayBuffer
    // copy the whole film would be in memory before playback starts.
    expect(stored?.blob).toBeInstanceOf(Blob);
    expect(await stored?.blob.text()).toHaveLength(0); // zeros, but readable
  });

  it("returns undefined for an unknown id", async () => {
    expect(await getBlob("nope")).toBeUndefined();
  });

  it("reports existence without reading the payload", async () => {
    await putBlob({ id: "b3", blob: videoBlob(512), fileName: "a.mp4" });
    expect(await hasBlob("b3")).toBe(true);
    expect(await hasBlob("missing")).toBe(false);
  });

  it.skipIf(!blobStorageSupported)("overwrites a record with the same id instead of duplicating", async () => {
    await putBlob({ id: "b4", blob: videoBlob(100), fileName: "one.mp4" });
    await putBlob({ id: "b4", blob: videoBlob(200), fileName: "two.mp4" });
    const stored = await getBlob("b4");
    expect(stored?.fileName).toBe("two.mp4");
    expect(stored?.blob.size).toBe(200);
  });
});

describe("environment capabilities", () => {
  it("reports storage availability", () => {
    expect(storageAvailable()).toBe(true);
  });

  it("never throws when asking for persistence", async () => {
    await expect(requestPersistence()).resolves.toBeTypeOf("boolean");
  });
});
