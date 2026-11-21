/**
 * One import flow, shared by every entry point.
 *
 * The library screen has its own import bar (folder picker, drag-and-drop), but
 * Ctrl+O and the empty state also need to import. Duplicating the merge/persist
 * logic in two places is how "works here, broken there" bugs appear, so the flow
 * lives here and both call it.
 */
import { useCallback, useState } from "react";
import {
  collectFromDataTransfer,
  expandArchives,
  importFiles,
  type ImportCandidate,
  type ImportProgress,
} from "../lib/importer";
import { useLibrary } from "./library";

export interface ImportController {
  progress: ImportProgress | null;
  busy: boolean;
  run: (candidates: ImportCandidate[]) => Promise<void>;
  runFiles: (files: FileList | File[]) => Promise<void>;
  runDrop: (transfer: DataTransfer) => Promise<void>;
  runArchive: (files: ImportCandidate[]) => Promise<void>;
}

export function useImport(notify: (message: string, kind?: "info" | "error") => void): ImportController {
  const { state, addTitles } = useLibrary();
  const [progress, setProgress] = useState<ImportProgress | null>(null);

  const run = useCallback(
    async (candidates: ImportCandidate[]) => {
      if (!candidates.length) {
        notify("No video files found in that selection.", "error");
        return;
      }
      try {
        setProgress({ phase: "scan", done: 0, total: candidates.length });
        const expanded = await expandArchives(candidates);
        const result = await importFiles(expanded, state.titles, {
          onProgress: setProgress,
        });
        addTitles(result.titles);
        const parts = [`${result.addedFiles} file${result.addedFiles === 1 ? "" : "s"} added`];
        if (result.skipped.length) parts.push(`${result.skipped.length} skipped`);
        notify(parts.join(" · "), result.addedFiles ? "info" : "error");
      } catch (error) {
        notify(error instanceof Error ? error.message : "Import failed", "error");
      } finally {
        setProgress(null);
      }
    },
    [addTitles, notify, state.titles],
  );

  const runFiles = useCallback(
    async (files: FileList | File[]) => {
      await run([...files].map((file) => ({ file, path: file.name })));
    },
    [run],
  );

  const runDrop = useCallback(
    async (transfer: DataTransfer) => {
      await run(await collectFromDataTransfer(transfer));
    },
    [run],
  );

  return {
    progress,
    busy: progress !== null,
    run,
    runFiles,
    runDrop,
    runArchive: run,
  };
}
