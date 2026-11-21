/**
 * Turning real-world file names into library entries.
 *
 * Scene releases are the messy part of any local media library, so parsing is
 * a pure function with an explicit, testable rule order:
 *
 *   1. strip the extension and any leading "[Group]" tags
 *   2. normalise separators (dots/underscores -> spaces) *outside* year brackets
 *   3. find the year (last 19xx/20xx token that is not part of a resolution)
 *   4. find SxxExx / "Season N Episode M" markers
 *   5. collect known quality/source/codec tokens as tags, remove them from the name
 *   6. split "Title" from "Title 2" only when a sequel marker follows a year
 *
 * Everything is heuristic and reversible: the original file name is stored on
 * the record, so a wrong guess never loses information — the user can rename.
 */
import type { MediaKind } from "./types";

const VIDEO_EXTENSIONS = [
  ".mp4", ".m4v", ".mkv", ".webm", ".mov", ".avi", ".ogv", ".ogg", ".ts", ".m2ts", ".flv", ".wmv",
] as const;

/** Tokens that describe the encode rather than the title. */
const QUALITY_TOKENS = [
  "2160p", "1440p", "1080p", "1080i", "720p", "576p", "480p", "4k", "uhd", "hdr", "hdr10", "dv",
  "dolbyvision", "10bit", "8bit",
] as const;

const SOURCE_TOKENS = [
  "bluray", "blu-ray", "bdrip", "brrip", "web-dl", "webdl", "webrip", "web", "hdtv", "dvdrip",
  "dvdscr", "hdcam", "camrip", "remux", "hdrip", "pdtv",
] as const;

const CODEC_TOKENS = [
  "x264", "x265", "h264", "h265", "hevc", "avc", "xvid", "divx", "av1", "vp9", "aac", "ac3",
  "dts", "ddp5", "dd5", "atmos", "truehd", "flac", "opus", "eac3",
] as const;

const RELEASE_SUFFIXES = [
  "proper", "repack", "extended", "remastered", "uncut", "unrated", "directors", "director's",
  "imax", "limited", "internal", "readnfo", "dubbed", "subbed", "multi", "dual",
] as const;

/** Language/region flags that scene groups append, e.g. "HIN-ENG". */
const LANGUAGE_TOKENS = ["hindi", "eng", "english", "tamil", "telugu", "hin", "esub", "msub"] as const;

const SEASON_EPISODE_PATTERNS: RegExp[] = [
  /\bs(\d{1,2})[\s._-]?e(\d{1,3})\b/i,
  /\b(\d{1,2})x(\d{1,3})\b/i,
  /\bseason[\s._-]?(\d{1,2})[\s._-]*(?:episode|ep|e)[\s._-]?(\d{1,3})\b/i,
  /\bepisode[\s._-]?(\d{1,3})\b/i,
];

const YEAR_PATTERN = /(?:^|[\s.([_-])((?:19|20)\d{2})(?=$|[\s.\]_)-])/g;

export interface ParsedName {
  name: string;
  kind: MediaKind;
  year?: number;
  season?: number;
  episode?: number;
  tags: string[];
}

export function isVideoFile(fileName: string, mime?: string): boolean {
  const lower = fileName.toLowerCase();
  if (VIDEO_EXTENSIONS.some((ext) => lower.endsWith(ext))) return true;
  // Some browsers report an empty type for .mkv; fall back to a video/* hint.
  return Boolean(mime?.startsWith("video/"));
}

export function stripExtension(fileName: string): string {
  const dot = fileName.lastIndexOf(".");
  return dot > 0 ? fileName.slice(0, dot) : fileName;
}

function tokensOf(lower: string, list: readonly string[]): string[] {
  return list.filter((token) => new RegExp(`(?:^|[\\s._\\-\\[\\]()])${escapeRegExp(token)}(?:$|[\\s._\\-\\[\\]()])`).test(lower));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Find the release year, preferring the last plausible one in the name. */
export function findYear(text: string): number | undefined {
  const matches = [...text.matchAll(YEAR_PATTERN)];
  if (!matches.length) return undefined;
  const last = matches[matches.length - 1];
  const value = Number(last?.[1]);
  return Number.isFinite(value) ? value : undefined;
}

/** Detect S01E02-style markers; returns undefined for movies. */
export function findSeasonEpisode(text: string): { season?: number; episode?: number } {
  for (const pattern of SEASON_EPISODE_PATTERNS) {
    const match = pattern.exec(text);
    if (!match) continue;
    if (match.length >= 3 && match[1] && match[2]) {
      const season = Number(match[1]);
      const episode = Number(match[2]);
      // 1x02 form only makes sense for small season numbers; reject "2049x1".
      if (season <= 50 && episode < 1000) return { season, episode };
    } else if (match[1]) {
      // "Episode 7" with no season.
      return { episode: Number(match[1]) };
    }
  }
  return {};
}

/**
 * Clean a raw file name into a display title.
 * Kept separate from {@link parseFileName} so the UI can show a preview while
 * the user edits an import.
 */
export function cleanTitle(fileName: string): string {
  let text = stripExtension(fileName);
  // Drop leading group tags: "[Group] Name" / "[Group]Name".
  text = text.replace(/^\s*(?:\[[^\]]*\]\s*)+/, "");
  // Release groups trail in brackets: "Name [YTS.MX]".
  text = text.replace(/\s*\[[^\]]*\]\s*$/g, "");
  // Dots/underscores used as separators become spaces, but keep decimals (5.1).
  text = text.replace(/[._]+/g, " ").replace(/\s{2,}/g, " ").trim();
  return text;
}

export function parseFileName(fileName: string): ParsedName {
  const cleaned = cleanTitle(fileName);
  const lower = cleaned.toLowerCase();

  const quality = tokensOf(lower, QUALITY_TOKENS);
  const source = tokensOf(lower, SOURCE_TOKENS);
  const codec = tokensOf(lower, CODEC_TOKENS);
  const release = tokensOf(lower, RELEASE_SUFFIXES);
  const language = tokensOf(lower, LANGUAGE_TOKENS);
  const tags = [...new Set([...quality, ...source, ...codec, ...release, ...language])];

  const { season, episode } = findSeasonEpisode(cleaned);
  const year = findYear(cleaned);

  // Build the title by removing the structural tokens, then collapsing space.
  let title = cleaned;

  // Drop the trailing release-group tag ("...-GROUP", "...-RARBG"). Two tokens
  // are enough: a group name never contains spaces, and keeping it would leak
  // into the display title and break series grouping.
  title = title.replace(/[-][A-Za-z0-9]{2,20}$/, " ");

  // Drop season/episode markers: they belong to the record, not the show name.
  title = title
    .replace(/\bs\d{1,2}[\s._-]?e\d{1,3}\b/gi, " ")
    .replace(/\b\d{1,2}x\d{1,3}\b/gi, " ")
    .replace(/\bseason[\s._-]?\d{1,2}(?:[\s._-]*(?:episode|ep|e)[\s._-]?\d{1,3})?\b/gi, " ")
    .replace(/\bepisode[\s._-]?\d{1,3}\b/gi, " ");
  const removable = [...tags, ...(year ? [String(year)] : [])];
  // Longest first so "blu-ray" is removed before "blu".
  removable
    .sort((a, b) => b.length - a.length)
    .forEach((token) => {
      title = title.replace(new RegExp(`(?:^|[\\s._\\-\\[\\]()])${escapeRegExp(token)}(?:$|[\\s._\\-\\[\\]()])`, "gi"), " ");
    });
  title = title
    .replace(/[\s._-]+/g, " ")
    .replace(/[()[\]]/g, " ")
    .replace(/\s{2,}/g, " ")
    .replace(/^[\s-]+|[\s-]+$/g, "")
    .trim();

  // If stripping ate everything (e.g. the file was named "1080p.mkv"), fall back
  // to the cleaned name rather than showing a blank row.
  if (!title) title = cleaned || stripExtension(fileName);

  const kind: MediaKind = season !== undefined || episode !== undefined ? "series" : "movie";
  return { name: title, kind, year, season, episode, tags };
}

/** Human-readable runtime, e.g. 3725 -> "1h 2m". */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${total % 60}s`;
  return `${total}s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded = Number.isInteger(value) ? String(value) : value.toFixed(1);
  return `${rounded} ${units[unit]}`;
}

/** 0..1 fraction watched, clamped; 0 when the runtime is unknown. */
export function progressFraction(seconds: number, duration: number): number {
  if (!duration || duration <= 0) return 0;
  return Math.min(1, Math.max(0, seconds / duration));
}

/** Stable, readable id from a name + size, so re-importing the same file is a no-op. */
export function makeId(...parts: (string | number)[]): string {
  const input = parts.join("|");
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}

/** Group episodes of one show into a series bucket by cleaned name + year. */
export function seriesKey(parsed: ParsedName): string {
  return `${parsed.name.toLowerCase()}|${parsed.year ?? ""}`;
}
