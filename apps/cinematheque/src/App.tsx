/**
 * App shell: sidebar + routed "screens" (single page, state-driven).
 *
 * There is no router dependency: three exclusive overlays (player, title sheet,
 * manage dialog) plus a filter in the library state are the whole navigation
 * model. That keeps the app to one bundle and makes back/forward predictable.
 *
 * Import is owned here through one `useImport` controller so the toolbar, the
 * empty state, drag-and-drop and Ctrl+O all share a single code path.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { CollectionsDialog } from "./components/CollectionsDialog";
import { Player } from "./components/Player";
import { Sidebar } from "./components/Sidebar";
import { TitleSheet } from "./components/TitleSheet";
import { LibraryScreen } from "./screens/Library";
import { useImport } from "./state/useImport";
import { useLibrary } from "./state/library";
import type { Title } from "./lib/types";

interface Toast {
  id: number;
  message: string;
  kind: "info" | "error";
}

export default function App() {
  const { state } = useLibrary();
  const [openTitle, setOpenTitle] = useState<Title | null>(null);
  const [playing, setPlaying] = useState<{ title: Title; fileId: string } | null>(null);
  const [managing, setManaging] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [dragging, setDragging] = useState(false);
  const pickerRef = useRef<HTMLInputElement | null>(null);
  const dragDepth = useRef(0);

  const notify = useCallback((message: string, kind: "info" | "error" = "info") => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, message, kind }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 4200);
  }, []);

  const importer = useImport(notify);

  // Ctrl/Cmd+O: open the picker. The empty state advertises this, so it must work.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "o") return;
      event.preventDefault();
      pickerRef.current?.click();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Drag-and-drop anywhere on the page, with depth counting so child leaves do
  // not flicker the overlay off.
  useEffect(() => {
    const hasFiles = (event: DragEvent) => Boolean(event.dataTransfer?.types.includes("Files"));
    const onEnter = (event: DragEvent) => {
      if (!hasFiles(event)) return;
      dragDepth.current += 1;
      setDragging(true);
    };
    const onLeave = () => {
      dragDepth.current = Math.max(0, dragDepth.current - 1);
      if (dragDepth.current === 0) setDragging(false);
    };
    const onOver = (event: DragEvent) => {
      if (hasFiles(event)) event.preventDefault();
    };
    const onDrop = (event: DragEvent) => {
      event.preventDefault();
      dragDepth.current = 0;
      setDragging(false);
      if (event.dataTransfer) void importer.runDrop(event.dataTransfer);
    };

    window.addEventListener("dragenter", onEnter);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("dragover", onOver);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragenter", onEnter);
      window.removeEventListener("dragleave", onLeave);
      window.removeEventListener("dragover", onOver);
      window.removeEventListener("drop", onDrop);
    };
  }, [importer]);

  // Keep an open sheet in sync with the store (e.g. after a rename).
  useEffect(() => {
    if (!openTitle) return;
    const fresh = state.titles.find((title) => title.id === openTitle.id);
    if (fresh && fresh !== openTitle) setOpenTitle(fresh);
    if (!fresh) setOpenTitle(null);
  }, [state.titles, openTitle]);

  return (
    <div className="shell">
      <Sidebar onManage={() => setManaging(true)} />

      <main className="shell__main">
        <LibraryScreen
          onOpenTitle={setOpenTitle}
          onNotify={notify}
          importer={importer}
          onPickFiles={() => pickerRef.current?.click()}
        />
      </main>

      {openTitle && !playing && (
        <TitleSheet
          title={openTitle}
          onClose={() => setOpenTitle(null)}
          onPlay={(fileId) => setPlaying({ title: openTitle, fileId })}
        />
      )}

      {playing && (
        <Player
          title={playing.title}
          fileId={playing.fileId}
          onPlayFile={(fileId) => setPlaying({ title: playing.title, fileId })}
          onClose={() => setPlaying(null)}
        />
      )}

      {managing && <CollectionsDialog onClose={() => setManaging(false)} />}

      <input
        ref={pickerRef}
        type="file"
        accept="video/*,.mkv,.m4v,.webm,.avi,.zip"
        multiple
        hidden
        onChange={(event) => {
          const files = event.target.files;
          event.target.value = "";
          if (files && files.length) void importer.runFiles(files);
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

      <div className="toasts" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast${toast.kind === "error" ? " toast--error" : ""}`} role="status">
            {toast.message}
          </div>
        ))}
      </div>
    </div>
  );
}
