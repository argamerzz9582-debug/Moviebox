import { useLibrary, type FilterKey } from "../state/library";

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "Everything" },
  { key: "movie", label: "Movies" },
  { key: "series", label: "Series" },
  { key: "inprogress", label: "Continue" },
  { key: "favourites", label: "Favourites" },
  { key: "unwatched", label: "Not started" },
  { key: "watched", label: "Finished" },
];

export function Sidebar({ onManage }: { onManage: () => void }) {
  const { state, dispatch, collections } = useLibrary();
  const counts = countByFilter();

  return (
    <aside className="shell__sidebar" aria-label="Library navigation">
      <div className="brand">
        <span className="brand__mark" />
        <div>
          <div className="brand__name">Cinémathèque</div>
          <div className="brand__tag">local library</div>
        </div>
      </div>

      <nav className="nav-group" aria-label="Filters">
        {FILTERS.map((filter) => (
          <button
            key={filter.key}
            className="nav-item"
            aria-current={state.filter === filter.key && !state.selectedCollection ? "true" : undefined}
            onClick={() => {
              dispatch({ type: "selectCollection", name: null });
              dispatch({ type: "filter", filter: filter.key });
            }}
          >
            <span>{filter.label}</span>
            <span className="nav-item__count">{counts[filter.key] ?? 0}</span>
          </button>
        ))}
      </nav>

      <div className="nav-group">
        <div className="nav-group__label">Collections</div>
        {collections.length === 0 && (
          <p style={{ padding: "0 10px", color: "var(--ink-faint)", fontSize: "var(--step--1)" }}>
            None yet — create one from a title.
          </p>
        )}
        {collections.map((name) => (
          <button
            key={name}
            className="nav-item"
            aria-current={state.selectedCollection === name ? "true" : undefined}
            onClick={() => dispatch({ type: "selectCollection", name })}
          >
            <span>{name}</span>
            <span className="nav-item__count">{(state.collections[name] ?? []).length}</span>
          </button>
        ))}
        <button className="nav-item" onClick={onManage}>
          <span>Manage…</span>
        </button>
      </div>
    </aside>
  );
}

function countByFilter(): Record<FilterKey, number> {
  const { state } = useLibrary();
  const counts: Record<FilterKey, number> = {
    all: state.titles.length,
    movie: 0,
    series: 0,
    unwatched: 0,
    inprogress: 0,
    watched: 0,
    favourites: 0,
  };
  for (const title of state.titles) {
    if (title.kind === "movie") counts.movie += 1;
    if (title.kind === "series") counts.series += 1;
    if (title.favourite) counts.favourites += 1;
    if (title.watched) counts.watched += 1;
    else if (title.progress > 0) counts.inprogress += 1;
    else counts.unwatched += 1;
  }
  return counts;
}
