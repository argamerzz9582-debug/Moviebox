/**
 * Parser tests.
 *
 * These cover the cases that actually break a local media library: scene
 * release names, season packs, bracketed groups, multi-language suffixes, and
 * the failure mode where every structural token is stripped out of the name.
 */
import { describe, expect, it } from "vitest";
import {
  cleanTitle,
  findSeasonEpisode,
  findYear,
  formatBytes,
  formatDuration,
  isVideoFile,
  makeId,
  parseFileName,
  progressFraction,
  seriesKey,
  stripExtension,
} from "../src/lib/parse";

describe("isVideoFile", () => {
  it("accepts common containers regardless of case", () => {
    expect(isVideoFile("Movie.MKV")).toBe(true);
    expect(isVideoFile("clip.webm")).toBe(true);
    expect(isVideoFile("a.b.c.mp4")).toBe(true);
  });

  it("rejects non-video files", () => {
    expect(isVideoFile("cover.jpg")).toBe(false);
    expect(isVideoFile("subs.srt")).toBe(false);
    expect(isVideoFile("archive.zip")).toBe(false);
  });

  it("falls back to the MIME type when the extension is unknown", () => {
    expect(isVideoFile("no-extension", "video/mp4")).toBe(true);
    expect(isVideoFile("no-extension", "application/octet-stream")).toBe(false);
  });
});

describe("stripExtension", () => {
  it("removes only the last extension", () => {
    expect(stripExtension("Blade.Runner.2049.2017.mkv")).toBe("Blade.Runner.2049.2017");
  });

  it("leaves dotfiles and extensionless names intact", () => {
    expect(stripExtension("noext")).toBe("noext");
    expect(stripExtension(".gitignore")).toBe(".gitignore");
  });
});

describe("cleanTitle", () => {
  it("drops leading group tags and trailing brackets", () => {
    expect(cleanTitle("[Group] The.Movie.2020.1080p.mkv")).toBe("The Movie 2020 1080p");
    expect(cleanTitle("The Movie (2020) [YTS.MX].mkv")).toBe("The Movie (2020)");
  });

  it("keeps decimal audio notation readable", () => {
    expect(cleanTitle("Movie.2020.5.1.mkv")).toBe("Movie 2020 5 1");
  });
});

describe("findYear", () => {
  it("finds a bracketed year", () => {
    expect(findYear("Blade Runner 2049 (2017)")).toBe(2017);
  });

  it("prefers the last plausible year", () => {
    expect(findYear("Movie 2019 2020 WEB-DL")).toBe(2020);
  });

  it("ignores resolutions and other numbers", () => {
    expect(findYear("Movie.1080p.WEB-DL")).toBeUndefined();
    expect(findYear("Movie.2160p")).toBeUndefined();
  });
});

describe("findSeasonEpisode", () => {
  it("reads SxxExx in several separator styles", () => {
    expect(findSeasonEpisode("Show S01E02 1080p")).toEqual({ season: 1, episode: 2 });
    expect(findSeasonEpisode("Show.s02e10.mkv")).toEqual({ season: 2, episode: 10 });
    expect(findSeasonEpisode("Show 2x03")).toEqual({ season: 2, episode: 3 });
  });

  it("reads spelled-out season/episode", () => {
    expect(findSeasonEpisode("Show Season 3 Episode 7")).toEqual({ season: 3, episode: 7 });
  });

  it("reads a bare episode marker", () => {
    expect(findSeasonEpisode("Show Episode 7")).toEqual({ episode: 7 });
  });

  it("returns nothing for a movie", () => {
    expect(findSeasonEpisode("Blade Runner 2049")).toEqual({});
  });
});

describe("parseFileName", () => {
  it("parses a movie release", () => {
    const parsed = parseFileName("Blade.Runner.2049.2017.1080p.BluRay.x264-GROUP.mkv");
    expect(parsed.name).toBe("Blade Runner 2049");
    expect(parsed.year).toBe(2017);
    expect(parsed.kind).toBe("movie");
    expect(parsed.tags).toEqual(expect.arrayContaining(["1080p", "bluray", "x264"]));
  });

  it("parses an episode and marks it a series", () => {
    const parsed = parseFileName("The.Bear.S02E05.720p.WEB-DL.AAC.mkv");
    expect(parsed.kind).toBe("series");
    expect(parsed.season).toBe(2);
    expect(parsed.episode).toBe(5);
    expect(parsed.name).toBe("The Bear");
  });

  it("handles multi-language suffixes", () => {
    const parsed = parseFileName("Movie.Name.2021.HIN-ENG.1080p.WEB-DL.mkv");
    expect(parsed.name).toMatch(/^Movie Name/);
    expect(parsed.tags).toContain("1080p");
  });

  it("falls back to the cleaned name when every token is structural", () => {
    const parsed = parseFileName("1080p.mkv");
    expect(parsed.name).toBe("1080p");
  });

  it("never returns an empty name", () => {
    for (const name of ["x.mkv", ".mp4", "S01E01.mkv", "2019.mkv"]) {
      expect(parseFileName(name).name.length).toBeGreaterThan(0);
    }
  });
});

describe("formatting helpers", () => {
  it("formats durations", () => {
    expect(formatDuration(3725)).toBe("1h 2m");
    expect(formatDuration(95)).toBe("1m 35s");
    expect(formatDuration(42)).toBe("42s");
    expect(formatDuration(0)).toBe("—");
    expect(formatDuration(Number.NaN)).toBe("—");
  });

  it("formats bytes", () => {
    expect(formatBytes(0)).toBe("—");
    expect(formatBytes(900)).toBe("900 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5 GB");
  });

  it("clamps progress fractions", () => {
    expect(progressFraction(0, 100)).toBe(0);
    expect(progressFraction(50, 0)).toBe(0);
    expect(progressFraction(200, 100)).toBe(1);
    expect(progressFraction(25, 100)).toBe(0.25);
  });
});

describe("identity helpers", () => {
  it("is stable for the same inputs and differs otherwise", () => {
    expect(makeId("a.mkv", 100)).toBe(makeId("a.mkv", 100));
    expect(makeId("a.mkv", 100)).not.toBe(makeId("b.mkv", 100));
    expect(makeId("a.mkv", 100)).not.toBe(makeId("a.mkv", 101));
  });

  it("groups episodes of one show under one key", () => {
    const one = parseFileName("Show.S01E01.mkv");
    const two = parseFileName("Show.S01E02.mkv");
    expect(seriesKey(one)).toBe(seriesKey(two));
    expect(seriesKey(parseFileName("Other.Show.S01E01.mkv"))).not.toBe(seriesKey(one));
  });
});
