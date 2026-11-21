/**
 * Import pipeline tests.
 *
 * Files are real `File` objects built from Blobs (jsdom supports them), and
 * `probeDuration` is stubbed because jsdom has no media pipeline — the rest of
 * the pipeline (dedupe, series merging, ordering) is exercised for real.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/lib/db", () => ({
  putBlob: vi.fn(async () => undefined),
  getBlob: vi.fn(async () => undefined),
  deleteBlob: vi.fn(async () => undefined),
}));

import { importFiles } from "../src/lib/importer";
import { putBlob } from "../src/lib/db";
import type { Title } from "../src/lib/types";

function videoFile(name: string, size = 1024, type = "video/mp4"): File {
  return new File([new Uint8Array(size)], name, { type });
}

/** Injected duration probe: jsdom has no media pipeline. */
const probe = vi.fn(async () => 5400);

beforeEach(() => {
  vi.clearAllMocks();
  probe.mockResolvedValue(5400);
});

describe("importFiles", () => {
  it("creates one movie title per file", async () => {
    const result = await importFiles(
      [
        { file: videoFile("Arrival.2016.1080p.mkv"), path: "Arrival.2016.1080p.mkv" },
        { file: videoFile("Dune.2021.2160p.mkv"), path: "Dune.2021.2160p.mkv" },
      ],
      [],
      { probe },
    );
    expect(result.titles).toHaveLength(2);
    expect(result.addedFiles).toBe(2);
    expect(result.titles.map((t) => t.name).sort()).toEqual(["Arrival", "Dune"]);
  });

  it("merges episodes of one show into a single title, ordered by episode", async () => {
    const result = await importFiles(
      [
        { file: videoFile("The.Bear.S02E07.mkv"), path: "ep7" },
        { file: videoFile("The.Bear.S02E05.mkv"), path: "ep5" },
        { file: videoFile("The.Bear.S02E06.mkv"), path: "ep6" },
      ],
      [],
      { probe },
    );
    expect(result.titles).toHaveLength(1);
    const show = result.titles[0]!;
    expect(show.kind).toBe("series");
    expect(show.files.map((f) => f.fileName)).toEqual([
      "The.Bear.S02E05.mkv",
      "The.Bear.S02E06.mkv",
      "The.Bear.S02E07.mkv",
    ]);
  });

  it("skips non-video files and reports them", async () => {
    const result = await importFiles(
      [
        { file: videoFile("Movie.2010.mkv"), path: "movie" },
        { file: videoFile("poster.jpg", 10, "image/jpeg"), path: "poster" },
        { file: videoFile("notes.txt", 10, "text/plain"), path: "notes" },
      ],
      [],
      { probe },
    );
    expect(result.titles).toHaveLength(1);
    expect(result.skipped.sort()).toEqual(["notes", "poster"]);
  });

  it("de-duplicates files already in the library", async () => {
    const existing: Title[] = [];
    const first = await importFiles([{ file: videoFile("Movie.2010.mkv", 2048), path: "m" }], existing, { probe });
    const second = await importFiles(
      [{ file: videoFile("Movie.2010.mkv", 2048), path: "m-again" }],
      first.titles,
      { probe },
    );
    expect(second.addedFiles).toBe(0);
    expect(second.skipped).toContain("m-again");
    expect(second.titles[0]?.files).toHaveLength(1);
  });

  it("appends a new quality of the same movie instead of duplicating the title", async () => {
    const first = await importFiles([{ file: videoFile("Dune.2021.1080p.mkv", 1000), path: "a" }], [], { probe });
    const second = await importFiles([{ file: videoFile("Dune.2021.2160p.mkv", 2000), path: "b" }], first.titles, { probe });
    expect(second.titles).toHaveLength(1);
    expect(second.titles[0]?.files).toHaveLength(2);
    expect(second.titles[0]?.tags).toEqual(expect.arrayContaining(["1080p", "2160p"]));
  });

  it("stores every blob so playback survives a reload", async () => {
    await importFiles([{ file: videoFile("A.2001.mkv"), path: "a" }], [], { probe });
    expect(putBlob).toHaveBeenCalledTimes(1);
    const arg = vi.mocked(putBlob).mock.calls[0]?.[0];
    expect(arg?.fileName).toBe("A.2001.mkv");
  });

  it("records the probed duration and derives quality from tags", async () => {
    const result = await importFiles([{ file: videoFile("Heat.1995.2160p.mkv"), path: "h" }], [], { probe });
    const file = result.titles[0]?.files[0];
    expect(file?.duration).toBe(5400);
    expect(file?.quality).toBe("2160p");
  });

  it("reports progress and finishes with a done phase", async () => {
    const phases: string[] = [];
    await importFiles([{ file: videoFile("A.2001.mkv"), path: "a" }], [], {
      probe,
      onProgress: (progress) => phases.push(progress.phase),
    });
    expect(phases).toContain("probe");
    expect(phases.at(-1)).toBe("done");
  });

  it("survives a file whose duration cannot be read", async () => {
    probe.mockResolvedValue(0);
    const result = await importFiles([{ file: videoFile("A.2001.mkv"), path: "a" }], [], { probe });
    expect(result.titles[0]?.files[0]?.duration).toBe(0);
  });

  it("does not mutate the existing titles it is given", async () => {
    const first = await importFiles([{ file: videoFile("Dune.2021.1080p.mkv", 1000), path: "a" }], [], { probe });
    const snapshot = JSON.stringify(first.titles);
    await importFiles([{ file: videoFile("Dune.2021.2160p.mkv", 2000), path: "b" }], first.titles, { probe });
    expect(JSON.stringify(first.titles)).toBe(snapshot);
  });
});
