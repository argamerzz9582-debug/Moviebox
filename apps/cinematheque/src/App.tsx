/**
 * App shell: sidebar + routed "screens" (single page, state-driven).
 *
 * There is no router dependency: three exclusive overlays (player, title sheet,
 * manage dialog) plus a filter in the library state are the whole navigation
 * model. That keeps the app to one bundle and makes back/forward predictable.
 */
import { useCallback, useEffect, useState } from "react";
import { CollectionsDialog } from "./components/CollectionsDialog";
import { Player } from "./components/Player";
import { Sidebar } from "./components/Sidebar";
import { TitleSheet } from "./components/TitleSheet";
import { LibraryScreen } from "./screens/Library";
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

  const notify = useCallback((message: string, kind: "info" | "error" = "info") => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, message, kind }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 4200);
  }, []);

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
        <LibraryScreen onOpenTitle={setOpenTitle} onNotify={notify} />
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
