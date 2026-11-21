/**
 * Library screen: the browsing surface.
 *
 * Owns the toolbar (search, sort, filters, view mode), the storage meter, and the
 * grid/rows switch. Title detail and playback are delegated upward so this file
 * stays about layout and discovery.
 */
import { useEffect, useState } from "react";
import { ImportBar } from "../components/ImportBar";
import { IconSearch } from "../components/icons";
import { TitleCard, TitleRow } from "../components/TitleCard";
import { formatBytes } from "../lib/parse";
import { storageEstimate } from "../lib/db";
import { useLibrary, type FilterKey, type SortKey } from "../state/library";
import type { Title } from "../lib/types";
import type { ImportController } from "../state/useImport";

const SORTS: { key: SortKey; label: string }[] = [
  { key: "recent", label: "Recently added" },
  { key: "title", label: "Title A–Z" },
  { key: "year", label: "Newest release" },
  { key: "progress", label: "Most watched" },
];

const CHIPS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "movie", label: "Movies" },
  { key: "series", label: "Series" },
  { key: "inprogress", label: "Continue watching" },
  { key: "favourites", label: "Favourites" },
];

interface LibraryProps {
  onOpenTitle: (title: Title) => void;
  onNotify: (message: string, kind?: "info" | "error") => void;
  importer: ImportController;
  onPickFiles: () => void;
}

export function LibraryScreen({ onOpenTitle, onNotify, importer, onPickFiles }: LibraryProps) {
  const { state, dispatch, visibleTitles, storageOk } = useLibrary();
  const hasTitles = state.titles.length > 0;
  const heading = state.selectedCollection ?? "Library";

  return (
    <>
      <header className="topbar">
        <h1 className="topbar__title">{heading}</h1>

        <div className="search">
          <span className="search__icon">
            <IconSearch />
          </span>
          <input
            type="search"
            value={state.query}
            onChange={(event) => dispatch({ type: "query", query: event.target.value })}
            placeholder="Search titles, years, tags…"
            aria-label="Search library"
          />
        </div>

        <ImportBar importer={importer} onNotify={onNotify} onPickFiles={onPickFiles} />
      </header>

      {!storageOk && (
        <div className="banner" role="status">
          Storage is unavailable in this browser session (private window?). The library will work but forget
          everything when you close the tab.
        </div>
      )}

      {!hasTitles ? (
        <EmptyLibrary onNotify={onNotify} importer={importer} onPickFiles={onPickFiles} />
      ) : (
        <>
          <div className="toolbar">
            <div className="chips" style={{ margin: 0 }} role="group" aria-label="Filter">
              {CHIPS.map((chip) => (
                <button
                  key={chip.key}
                  className="chip"
                  aria-pressed={state.filter === chip.key}
                  onClick={() => dispatch({ type: "filter", filter: chip.key })}
                >
                  {chip.label}
                </button>
              ))}
            </div>

            <span className="player__spacer" />

            <StorageMeter />

            <select
              value={state.sort}
              onChange={(event) => dispatch({ type: "sort", sort: event.target.value as SortKey })}
              aria-label="Sort library"
              style={{
                padding: "7px 11px",
                borderRadius: "var(--radius-full)",
                border: "1px solid var(--line)",
                background: "var(--bg-raised)",
                fontSize: "var(--step--1)",
              }}
            >
              {SORTS.map((sort) => (
                <option key={sort.key} value={sort.key}>
                  {sort.label}
                </option>
              ))}
            </select>

            <div role="group" aria-label="View mode" style={{ display: "flex", gap: 4 }}>
              {(["grid", "rows"] as const).map((mode) => (
                <button
                  key={mode}
                  className="chip"
                  aria-pressed={state.viewMode === mode}
                  onClick={() => dispatch({ type: "viewMode", mode })}
                >
                  {mode === "grid" ? "Grid" : "List"}
                </button>
              ))}
            </div>
          </div>

          {visibleTitles.length === 0 ? (
            <div className="empty">
              <h2>Nothing matches</h2>
              <p>
                No titles match {state.query ? `“${state.query}”` : "this filter"}. Try a different search or
                filter.
              </p>
              <div className="empty__actions">
                <button className="btn" onClick={() => dispatch({ type: "query", query: "" })}>
                  Clear search
                </button>
                <button
                  className="btn btn--ghost"
                  onClick={() => {
                    dispatch({ type: "selectCollection", name: null });
                    dispatch({ type: "filter", filter: "all" });
                  }}
                >
                  Show everything
                </button>
              </div>
            </div>
          ) : state.viewMode === "rows" ? (
            <div className="rows">
              {visibleTitles.map((title) => (
                <TitleRow key={title.id} title={title} onOpen={onOpenTitle} />
              ))}
            </div>
          ) : (
            <>
              <div className="grid">
                {visibleTitles.map((title) => (
                  <TitleCard key={title.id} title={title} onOpen={onOpenTitle} />
                ))}
              </div>
              <p style={{ marginTop: 22, color: "var(--ink-faint)", fontSize: "var(--step--1)" }}>
                {visibleTitles.length} title{visibleTitles.length === 1 ? "" : "s"}
              </p>
            </>
          )}
        </>
      )}
    </>
  );
}

/** Shows how much of the browser's storage quota the library uses. */
function StorageMeter() {
  const [estimate, setEstimate] = useState<{ usage: number; quota: number } | undefined>(undefined);

  useEffect(() => {
    let active = true;
    void storageEstimate().then((value) => {
      if (active) setEstimate(value);
    });
    return () => {
      active = false;
    };
  }, []);

  const { state } = useLibrary();
  // Re-read whenever the library grows: a rough signal is enough here.
  useEffect(() => {
    void storageEstimate().then(setEstimate);
  }, [state.titles.length]);

  if (!estimate || !estimate.quota) return null;
  const percent = Math.min(100, (estimate.usage / estimate.quota) * 100);

  return (
    <span className="storage-meter" title={`${formatBytes(estimate.usage)} of ${formatBytes(estimate.quota)} used`}>
      <span className="storage-meter__track" aria-hidden="true">
        <span className="storage-meter__fill" style={{ width: `${Math.max(1, percent)}%` }} />
      </span>
      {formatBytes(estimate.usage)} used
    </span>
  );
}

function EmptyLibrary({
  onNotify,
  importer,
  onPickFiles,
}: {
  onNotify: (message: string, kind?: "info" | "error") => void;
  importer: ImportController;
  onPickFiles: () => void;
}) {
  return (
    <div className="empty">
      <h2>Your library is empty</h2>
      <p>
        Add your own video files — a folder of movies, a season pack, or a single file. Everything is parsed,
        stored and played on this device; nothing is uploaded and no account is needed.
      </p>
      <div className="empty__actions">
        <ImportBar importer={importer} onNotify={onNotify} onPickFiles={onPickFiles} />
      </div>
      <p style={{ fontSize: "var(--step--1)", color: "var(--ink-faint)" }}>
        Tip: drop files anywhere on this page. Playable formats depend on your browser — MP4/H.264 is the
        safest; MKV and HEVC vary by platform.
      </p>
    </div>
  );
}
