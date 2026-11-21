/**
 * Import affordances: folder picker, file picker, and progress.
 *
 * The actual import runs through the shared `useImport` controller (owned by
 * App), so drag-and-drop, Ctrl+O and these buttons cannot drift apart.
 *
 * Folder picking uses the File System Access API where available and silently
 * falls back to a multi-file input elsewhere (Safari/Firefox), so the button
 * never lies about what it will do.
 */
import { useCallback, useEffect, useState } from "react";
import type { ImportCandidate } from "../lib/importer";
import type { ImportController } from "../state/useImport";
import { IconFolder, IconPlus } from "./icons";

interface FileSystemHandleLike {
  kind: "file" | "directory";
  name: string;
}

interface DirectoryPickerWindow {
  showDirectoryPicker?: (options?: { mode?: "read" | "readwrite" }) => Promise<FileSystemDirectoryHandle>;
}

async function filesFromDirectoryHandle(handle: FileSystemDirectoryHandle): Promise<ImportCandidate[]> {
  const out: ImportCandidate[] = [];
  const iterator = (handle as unknown as { entries: () => AsyncIterable<[string, FileSystemHandleLike]> }).entries();
  for await (const [name, child] of iterator) {
    if (child.kind === "file") {
      const file = await (child as unknown as { getFile: () => Promise<File> }).getFile();
      out.push({ file, path: name });
    } else if (child.kind === "directory") {
      out.push(...(await filesFromDirectoryHandle(child as unknown as FileSystemDirectoryHandle)));
    }
  }
  return out;
}

interface ImportBarProps {
  importer: ImportController;
  onNotify: (message: string, kind?: "info" | "error") => void;
  onPickFiles: () => void;
}

export function ImportBar({ importer, onNotify, onPickFiles }: ImportBarProps) {
  const [canPickFolder, setCanPickFolder] = useState(false);
  const { progress } = importer;

  useEffect(() => {
    setCanPickFolder(typeof (window as unknown as DirectoryPickerWindow).showDirectoryPicker === "function");
  }, []);

  const pickFolder = useCallback(async () => {
    const picker = (window as unknown as DirectoryPickerWindow).showDirectoryPicker;
    if (!picker) {
      onPickFiles();
      return;
    }
    try {
      const handle = await picker({ mode: "read" });
      await importer.run(await filesFromDirectoryHandle(handle));
    } catch (error) {
      // AbortError means the user cancelled: not an error to report.
      if ((error as DOMException)?.name !== "AbortError") {
        onNotify("Could not read that folder. Try the file picker instead.", "error");
      }
    }
  }, [importer, onNotify, onPickFiles]);

  const percent = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
      {canPickFolder ? (
        <button className="btn btn--primary" onClick={() => void pickFolder()}>
          <IconFolder width={16} height={16} />
          Add folder
        </button>
      ) : (
        <button className="btn btn--primary" onClick={onPickFiles}>
          <IconPlus width={16} height={16} />
          Add files
        </button>
      )}
      {canPickFolder && (
        <button className="btn" onClick={onPickFiles}>
          <IconPlus width={16} height={16} />
          Add files
        </button>
      )}
      {progress && (
        <span className="progress-pill" role="status" aria-live="polite">
          <span>
            {progress.phase === "probe" ? "Reading" : progress.phase === "store" ? "Saving" : "Working"}…{" "}
            {progress.done}/{progress.total}
          </span>
          <span className="progress-pill__track">
            <span className="progress-pill__fill" style={{ width: `${percent}%` }} />
          </span>
        </span>
      )}
    </div>
  );
}
