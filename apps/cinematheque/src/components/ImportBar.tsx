/**
 * Import affordances: folder picker, file picker, drag-and-drop overlay.
 *
 * Folder picking uses the File System Access API where available and silently
 * falls back to a multi-file input elsewhere (Safari/Firefox), so the button
 * never lies about what it will do.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  collectFromDataTransfer,
  expandArchives,
  importFiles,
  type ImportCandidate,
  type ImportProgress,
} from "../lib/importer";
import { useLibrary } from "../state/library";
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
  // entries() is not in every TS DOM lib version; treat the handle loosely.
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

export function ImportBar({ onNotify }: { onNotify: (message: string, kind?: "info" | "error") => void }) {
  const { state, addTitles } = useLibrary();
  const [progress, setProgress] = useState<ImportProgress | null>(null);
  const [dragging, setDragging] = useState(false);
  const [canPickFolder, setCanPickFolder] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const dragDepth = useRef(0);

  useEffect(() => {
    setCanPickFolder(typeof (window as unknown as DirectoryPickerWindow).showDirectoryPicker === "function");
  }, []);

  const runImport = useCallback(
    async (candidates: ImportCandidate[]) => {
      if (!candidates.length) {
        onNotify("No video files found in that selection.", "error");
        return;
      }
      try {
        setProgress({ phase: "scan", done: 0, total: candidates.length });
        const expanded = await expandArchives(candidates);
        const result = await importFiles(expanded, state.titles, setProgress);
        addTitles(result.titles);
        const parts = [`${result.addedFiles} file${result.addedFiles === 1 ? "" : "s"} added`];
        if (result.skipped.length) parts.push(`${result.skipped.length} skipped`);
        onNotify(parts.join(" · "));
      } catch (error) {
        onNotify(error instanceof Error ? error.message : "Import failed", "error");
      } finally {
        setProgress(null);
      }
    },
    [addTitles, onNotify, state.titles],
  );

  // Drag-and-drop on the window, with depth counting so child leaves don't flicker.
  useEffect(() => {
    const onDragEnter = (event: DragEvent) => {
      if (!event.dataTransfer?.types.includes("Files")) return;
      dragDepth.current += 1;
      setDragging(true);
    };
    const onDragLeave = () => {
      dragDepth.current = Math.max(0, dragDepth.current - 1);
      if (dragDepth.current === 0) setDragging(false);
    };
    const onDragOver = (event: DragEvent) => {
      if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
    };
    const onDrop = (event: DragEvent) => {
      event.preventDefault();
      dragDepth.current = 0;
      setDragging(false);
      if (!event.dataTransfer) return;
      void (async () => {
        void runImport(await collectFromDataTransfer(event.dataTransfer!));
      })();
    };

    window.addEventListener("dragenter", onDragEnter);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("dragover", onDragOver);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragenter", onDragEnter);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("drop", onDrop);
    };
  }, [runImport]);

  const pickFolder = useCallback(async () => {
    const picker = (window as unknown as DirectoryPickerWindow).showDirectoryPicker;
    if (!picker) {
      inputRef.current?.click();
      return;
    }
    try {
      const handle = await picker({ mode: "read" });
      const candidates = await filesFromDirectoryHandle(handle);
      await runImport(candidates);
    } catch (error) {
      // AbortError means the user cancelled: that is not an error to report.
      if ((error as DOMException)?.name !== "AbortError") {
        onNotify("Could not read that folder. Try the file picker instead.", "error");
      }
    }
  }, [onNotify, runImport]);

  const percent = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <button className="btn btn--primary" onClick={() => void pickFolder()}>
          <IconFolder width={16} height={16} />
          {canPickFolder ? "Add folder" : "Add files"}
        </button>
        <button className="btn" onClick={() => inputRef.current?.click()}>
          <IconPlus width={16} height={16} />
          Add files
        </button>
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

      <input
        ref={inputRef}
        type="file"
        accept="video/*,.mkv,.m4v,.webm,.avi,.zip"
        multiple
        hidden
        onChange={(event) => {
          const files = [...(event.target.files ?? [])].map((file) => ({ file, path: file.name }));
          event.target.value = "";
          void runImport(files);
        }}
      />

      {dragging && (
        <div className="dropzone" aria-hidden="true">
          <div className="dropzone__inner">
            Drop videos here
            <div style={{ fontSize: "var(--step-0)", color: "var(--ink-muted)", marginTop: 8 }}>
              folders, files or a .zip season pack
            </div>
          </div>
        </div>
      )}
    </>
  );
}
