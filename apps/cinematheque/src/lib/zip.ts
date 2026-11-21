/**
 * Tiny ZIP-aware import helper.
 *
 * People keep "season packs" as .zip, so dropping one should just work. jszip is
 * lazy-loaded: the 100 KB it costs is only paid when the user actually drops an
 * archive, never on first paint.
 */
import { isVideoFile } from "./parse";

const MAX_ENTRIES = 5000;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024; // 8 GB guard rail

export async function extractVideosFromZip(zipFile: File): Promise<File[]> {
  const { default: JSZip } = await import("jszip");
  const archive = await JSZip.loadAsync(zipFile);
  const out: File[] = [];
  let total = 0;

  for (const entry of Object.values(archive.files)) {
    if (out.length >= MAX_ENTRIES) break;
    if (entry.dir) continue;
    if (!isVideoFile(entry.name)) continue;

    const blob = await entry.async("blob");
    total += blob.size;
    if (total > MAX_TOTAL_BYTES) break;

    // Keep only the base name: paths inside an archive are noise for display.
    const baseName = entry.name.split("/").pop() ?? entry.name;
    out.push(new File([blob], baseName, { type: mimeFor(baseName) }));
  }
  return out;
}

function mimeFor(fileName: string): string {
  const ext = fileName.toLowerCase().split(".").pop() ?? "";
  switch (ext) {
    case "mkv":
      return "video/x-matroska";
    case "webm":
      return "video/webm";
    case "mov":
      return "video/quicktime";
    case "avi":
      return "video/x-msvideo";
    case "ts":
    case "m2ts":
      return "video/mp2t";
    case "ogv":
    case "ogg":
      return "video/ogg";
    default:
      return "video/mp4";
  }
}
