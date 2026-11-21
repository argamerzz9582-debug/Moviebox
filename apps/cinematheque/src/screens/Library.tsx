/**
 * Library screen: the browsing surface.
 *
 * Owns the topbar (search, sort, filters) and renders either the empty state or
 * the poster grid. Title detail and playback are delegated upward so this file
 * stays about layout and discovery.
 */
import { ImportBar } from "../components/ImportBar";
import { IconSearch } from "../components/icons";
import { TitleCard } from "../components/TitleCard";
import { useLibrary, type SortKey } from "../state/library";
import type { Title } from "../lib/types";

const SORTS: { key: SortKey; label: string }[] = [
  { key: "recent", label: "Recently added" },
  { key: "title", label: "Title A–Z" },
  { key: "year", label: "Newest release" },
  { key: "progress", label: "Most watched" },
];

interface LibraryProps {
  onOpenTitle: (title: Title) => void;
  onNotify: (message: string, kind?: "info" | "error") => void;
}

export function LibraryScreen({ onOpenTitle, onNotify }: LibraryProps) {
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

        <select
          value={state.sort}
          onChange={(event) => dispatch({ type: "sort", sort: event.target.value as SortKey })}
          aria-label="Sort library"
          style={{
            padding: "9px 12px",
            borderRadius: "var(--radius-full)",
            border: "1px solid var(--line)",
            background: "var(--bg-raised)",
          }}
        >
          {SORTS.map((sort) => (
            <option key={sort.key} value={sort.key}>
              {sort.label}
            </option>
          ))}
        </select>

        <ImportBar onNotify={onNotify} />
      </header>

      {!storageOk && (
        <div className="banner" role="status">
          Storage is unavailable in this browser session (private window?). The library will work but forget
          everything when you close the tab.
        </div>
      )}

      {!hasTitles ? (
        <EmptyLibrary onNotify={onNotify} />
      ) : visibleTitles.length === 0 ? (
        <div className="empty">
          <h2>Nothing matches</h2>
          <p>
            No titles match “{state.query || state.filter}”. Try a different search or filter.
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
      ) : (
        <>
          <div className="chips" role="group" aria-label="Filter">
            {[
              { key: "all", label: "All" },
              { key: "movie", label: "Movies" },
              { key: "series", label: "Series" },
              { key: "inprogress", label: "Continue watching" },
              { key: "watched", label: "Finished" },
            ].map((chip) => (
              <button
                key={chip.key}
                className="chip"
                aria-pressed={state.filter === chip.key}
                onClick={() => dispatch({ type: "filter", filter: chip.key as typeof state.filter })}
              >
                {chip.label}
              </button>
            ))}
            <span style={{ marginLeft: "auto", alignSelf: "center", color: "var(--ink-faint)", fontSize: "var(--step--1)" }}>
              {visibleTitles.length} title{visibleTitles.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="grid">
            {visibleTitles.map((title) => (
              <TitleCard key={title.id} title={title} onOpen={onOpenTitle} />
            ))}
          </div>
        </>
      )}
    </>
  );
}

function EmptyLibrary({ onNotify }: { onNotify: (message: string, kind?: "info" | "error") => void }) {
  return (
    <div className="empty">
      <h2>Your library is empty</h2>
      <p>
        Add your own video files — a folder of movies, a season pack, or a single file. Everything is parsed,
        stored and played on this device; nothing is uploaded and no account is needed.
      </p>
      <div className="empty__actions">
        <ImportBar onNotify={onNotify} />
      </div>
      <p style={{ fontSize: "var(--step--1)", color: "var(--ink-faint)" }}>
        Tip: drop files anywhere on this page, or press <kbd>Ctrl</kbd>+<kbd>O</kbd>.
      </p>
    </div>
  );
}
