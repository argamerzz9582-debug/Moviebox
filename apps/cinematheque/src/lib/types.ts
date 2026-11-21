/**
 * Domain types for the media library.
 *
 * The library is *local-first*: every record is derived from a File/Blob the
 * user picked from their own device. Nothing here fetches remote metadata, and
 * there is no account concept — the "source of truth" is IndexedDB plus the
 * File System Access handles the user grants.
 */

export type MediaKind = "movie" | "series" | "unknown";

/** A single playable file. One title can own several (different qualities). */
export interface MediaFile {
  id: string;
  titleId: string;
  /** File name exactly as it appears on disk, kept for transparency. */
  fileName: string;
  /** Bytes; 0 when unknown (e.g. a synthetic test entry). */
  size: number;
  /** Seconds; 0 when not known yet. */
  duration: number;
  /** Container/quality guess from the name, e.g. "1080p", "WEB-DL". */
  quality?: string;
  /** MIME hint recorded at import time. */
  mime: string;
}

/** One library row: a movie, or a series container for episodes. */
export interface Title {
  id: string;
  kind: MediaKind;
  /** Clean display name, e.g. "Blade Runner 2049". */
  name: string;
  /** Release year when it could be parsed from the name. */
  year?: number;
  /** Season number for series episodes; undefined for movies. */
  season?: number;
  /** Episode number for series episodes. */
  episode?: number;
  /** Free-form tags parsed from the file name (resolution, source, codec). */
  tags: string[];
  /** ISO timestamp of import, for "recently added" ordering. */
  addedAt: string;
  /** Wall-clock seconds of the last playback position (resume support). */
  progress: number;
  /** True once progress reaches the last 5% of the runtime. */
  watched: boolean;
  /** Optional user override of the parsed name (rename support). */
  displayName?: string;
  files: MediaFile[];
}

/** Progress bookkeeping kept separate so a watch event is a cheap write. */
export interface ProgressRecord {
  titleId: string;
  seconds: number;
  duration: number;
  updatedAt: string;
}

export interface LibrarySnapshot {
  titles: Title[];
  progress: Record<string, ProgressRecord>;
  /** Collection names the user created manually. */
  collections: Record<string, string[]>;
}

export const EMPTY_LIBRARY: LibrarySnapshot = { titles: [], progress: {}, collections: {} };
