/**
 * Import pipeline: File[] -> library entries (+ persisted blobs).
 *
 * Deliberately browser-only concerns stay here so the parsing layer stays pure:
 *   - accepts files from a folder picker, a drag-and-drop, or a .zip
 *   - skips non-video files and de-duplicates by name+size hash
 *   - reads duration by mounting a hidden <video> (metadata only, no playback)
 *   - stores the blob so playback survives a reload
 *
 * Every step is cancellable through the `onProgress` callback returning false,
 * because a 200-file folder can take a while to walk.
 */
import { getBlob, putBlob } from "./db";
import { isVideoFile, makeId, parseFileName, seriesKey } from "./parse";
import type { MediaFile, Title } from "./types";
import { extractVideosFromZip } from "./zip";

export interface ImportCandidate {
  file: File;
  /** Path inside a picked folder, used only for duplicate detection/messages. */
  path: string;
}

export interface ImportProgress {
  phase: "scan" | "probe" | "store" | "done";
  done: number;
  total: number;
  current?: string;
}

export interface ImportResult {
  titles: Title[];
  skipped: string[];
  addedFiles: number;
}

/** Read duration + dimensions from a blob without keeping the element around. */
export function probeDuration(blob: Blob): Promise<number> {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(blob);
    const video = document.createElement("video");
    video.preload = "metadata";
    let settled = false;

    const finish = (seconds: number) => {
      if (settled) return;
      settled = true;
      video.removeAttribute("src");
      video.load?.();
      URL.revokeObjectURL(url);
      resolve(Number.isFinite(seconds) && seconds > 0 ? seconds : 0);
    };

    // A file we cannot decode still belongs in the library: record 0 seconds.
    const timer = setTimeout(() => finish(0), 8000);
    video.onloadedmetadata = () => {
      clearTimeout(timer);
      finish(video.duration);
    };
    video.onerror = () => {
      clearTimeout(timer);
      finish(0);
    };
    video.src = url;
  });
}

/** Walk a DataTransfer (drag-drop) into import candidates, recursing into folders. */
export async function collectFromDataTransfer(transfer: DataTransfer): Promise<ImportCandidate[]> {
  const entries = [...(transfer.items ?? [])]
    .map((item) => (item.kind === "file" ? (item.webkitGetAsEntry?.() ?? null) : null))
    .filter((entry): entry is FileSystemEntry => entry !== null);
  if (!entries.length) {
    return [...transfer.files].map((file) => ({ file, path: file.name }));
  }
  const out: ImportCandidate[] = [];
  for (const entry of entries) await walkEntry(entry, out);
  return out;
}

async function walkEntry(entry: FileSystemEntry, out: ImportCandidate[]): Promise<void> {
  if (entry.isFile) {
    const file = await new Promise<File | null>((resolve) => (entry as FileSystemFileEntry).file(resolve, () => resolve(null)));
    if (file) out.push({ file, path: entry.fullPath });
    return;
  }
  if (entry.isDirectory) {
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    const children = await new Promise<FileSystemEntry[]>((resolve) => reader.readEntries(resolve, () => resolve([])));
    for (const child of children) await walkEntry(child, out);
  }
}

/** Expand any .zip in the candidate list into the video files it contains. */
export async function expandArchives(candidates: ImportCandidate[]): Promise<ImportCandidate[]> {
  const out: ImportCandidate[] = [];
  for (const candidate of candidates) {
    if (candidate.file.name.toLowerCase().endsWith(".zip")) {
      const inner = await extractVideosFromZip(candidate.file);
      out.push(...inner.map((file) => ({ file, path: `${candidate.path}!${file.name}` })));
    } else {
      out.push(candidate);
    }
  }
  return out;
}

/**
 * Merge a batch of video files into titles.
 *
 * Episodes of one show collapse into a single series title (files appended),
 * which is how a local library should behave — one card per show, not 24.
 */
export interface ImportOptions {
  onProgress?: (progress: ImportProgress) => void;
  /** Overridable so tests (and future native probes) do not need a DOM. */
  probe?: (blob: Blob) => Promise<number>;
}

export async function importFiles(
  candidates: ImportCandidate[],
  existing: Title[],
  options: ImportOptions | ((progress: ImportProgress) => void) = {},
): Promise<ImportResult> {
  // Back-compat: the third argument used to be the progress callback alone.
  const { onProgress, probe = probeDuration } =
    typeof options === "function" ? { onProgress: options, probe: probeDuration } : options;
  const videos = candidates.filter((candidate) => isVideoFile(candidate.file.name, candidate.file.type));
  const skipped = candidates.filter((c) => !videos.includes(c)).map((c) => c.path);

  const byTitleId = new Map<string, Title>(existing.map((title) => [title.id, structuredCloneTitle(title)]));
  const knownFileIds = new Set(existing.flatMap((title) => title.files.map((file) => file.id)));

  let addedFiles = 0;
  const total = videos.length;

  for (let index = 0; index < videos.length; index += 1) {
    const { file, path } = videos[index]!;
    onProgress?.({ phase: "probe", done: index, total, current: path });

    const parsed = parseFileName(file.name);
    const fileId = makeId(file.name, file.size);

    if (knownFileIds.has(fileId)) {
      skipped.push(path);
      continue;
    }
    knownFileIds.add(fileId);

    const duration = await probe(file);

    const titleId =
      parsed.kind === "series"
        ? makeId("series", seriesKey(parsed))
        : makeId("title", parsed.name.toLowerCase(), parsed.year ?? "");

    let title = byTitleId.get(titleId);
    if (!title) {
      title = {
        id: titleId,
        kind: parsed.kind,
        name: parsed.name,
        year: parsed.year,
        season: parsed.season,
        episode: parsed.episode,
        tags: parsed.tags,
        addedAt: new Date().toISOString(),
        progress: 0,
        watched: false,
        files: [],
      };
      byTitleId.set(titleId, title);
    } else {
      // Keep tags in sync as new episodes bring new info.
      title.tags = [...new Set([...title.tags, ...parsed.tags])];
    }

    const mediaFile: MediaFile = {
      id: fileId,
      titleId,
      fileName: file.name,
      size: file.size,
      duration,
      quality: parsed.tags.find((tag) => /^\d{3,4}p$|^4k$|^uhd$/.test(tag)),
      mime: file.type || "video/mp4",
    };
    title.files.push(mediaFile);
    addedFiles += 1;

    onProgress?.({ phase: "store", done: index, total, current: file.name });
    await putBlob({ id: fileId, blob: file, fileName: file.name });
  }

  // Sort episodes inside a series so "next episode" is deterministic.
  for (const title of byTitleId.values()) {
    if (title.kind === "series") {
      title.files.sort((a, b) => episodeOrder(a.fileName) - episodeOrder(b.fileName));
    }
  }

  onProgress?.({ phase: "done", done: total, total });
  return { titles: [...byTitleId.values()], skipped, addedFiles };
}

function episodeOrder(fileName: string): number {
  const parsed = parseFileName(fileName);
  return (parsed.season ?? 0) * 1000 + (parsed.episode ?? 0);
}

function structuredCloneTitle(title: Title): Title {
  return { ...title, tags: [...title.tags], files: title.files.map((file) => ({ ...file })) };
}

/** Does the blob still exist for this id (i.e. will playback work after reload)? */
export async function hasStoredBlob(id: string): Promise<boolean> {
  return Boolean(await getBlob(id));
}
