/**
 * Library state.
 *
 * A tiny reducer + context instead of a state library: the whole app has one
 * store, and every mutation is an explicit action that is also easy to test.
 * Persistence is fire-and-forget on the resulting snapshot.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { clearAll, deleteBlob, loadSnapshot, saveSnapshot, storageAvailable } from "../lib/db";
import type { LibrarySnapshot, ProgressRecord, Title } from "../lib/types";
import { EMPTY_LIBRARY } from "../lib/types";

export type SortKey = "recent" | "title" | "year" | "progress";
export type FilterKey = "all" | "movie" | "series" | "unwatched" | "inprogress" | "watched";

interface State extends LibrarySnapshot {
  status: "loading" | "ready";
  sort: SortKey;
  filter: FilterKey;
  query: string;
  selectedCollection: string | null;
}

type Action =
  | { type: "hydrate"; snapshot: LibrarySnapshot }
  | { type: "replaceTitles"; titles: Title[] }
  | { type: "removeTitle"; id: string }
  | { type: "renameTitle"; id: string; name: string }
  | { type: "setProgress"; record: ProgressRecord }
  | { type: "toggleWatched"; id: string }
  | { type: "createCollection"; name: string }
  | { type: "deleteCollection"; collection: string }
  | { type: "toggleInCollection"; collection: string; titleId: string }
  | { type: "reset" }
  | { type: "sort"; sort: SortKey }
  | { type: "filter"; filter: FilterKey }
  | { type: "query"; query: string }
  | { type: "selectCollection"; name: string | null };

const INITIAL: State = {
  ...EMPTY_LIBRARY,
  status: "loading",
  sort: "recent",
  filter: "all",
  query: "",
  selectedCollection: null,
};

/** Everything above 95% counts as watched; below 1% is "not started". */
export const WATCHED_THRESHOLD = 0.95;

export function libraryReducer(state: State, action: Action): State {
  switch (action.type) {
    case "hydrate":
      return { ...state, ...action.snapshot, status: "ready" };
    case "replaceTitles":
      return { ...state, titles: action.titles };
    case "removeTitle": {
      const progress = { ...state.progress };
      delete progress[action.id];
      const collections = Object.fromEntries(
        Object.entries(state.collections).map(([name, ids]) => [name, ids.filter((id) => id !== action.id)]),
      );
      return { ...state, titles: state.titles.filter((title) => title.id !== action.id), progress, collections };
    }
    case "renameTitle":
      return {
        ...state,
        titles: state.titles.map((title) =>
          title.id === action.id ? { ...title, displayName: action.name.trim() || undefined } : title,
        ),
      };
    case "setProgress": {
      const { record } = action;
      const duration = record.duration || 0;
      const fraction = duration > 0 ? record.seconds / duration : 0;
      const watched = fraction >= WATCHED_THRESHOLD;
      return {
        ...state,
        progress: { ...state.progress, [record.titleId]: record },
        titles: state.titles.map((title) =>
          title.id === record.titleId
            ? { ...title, progress: record.seconds, watched: watched || title.watched }
            : title,
        ),
      };
    }
    case "toggleWatched":
      return {
        ...state,
        titles: state.titles.map((title) => (title.id === action.id ? { ...title, watched: !title.watched } : title)),
      };
    case "createCollection": {
      const name = action.name.trim();
      if (!name || state.collections[name]) return state;
      return { ...state, collections: { ...state.collections, [name]: [] } };
    }
    case "deleteCollection": {
      const collections = { ...state.collections };
      delete collections[action.collection];
      return {
        ...state,
        collections,
        selectedCollection: state.selectedCollection === action.collection ? null : state.selectedCollection,
      };
    }
    case "toggleInCollection": {
      const current = state.collections[action.collection] ?? [];
      const next = current.includes(action.titleId)
        ? current.filter((id) => id !== action.titleId)
        : [...current, action.titleId];
      return { ...state, collections: { ...state.collections, [action.collection]: next } };
    }
    case "reset":
      return { ...INITIAL, status: "ready" };
    case "sort":
      return { ...state, sort: action.sort };
    case "filter":
      return { ...state, filter: action.filter };
    case "query":
      return { ...state, query: action.query };
    case "selectCollection":
      return { ...state, selectedCollection: action.name };
    default:
      return state;
  }
}

/** Pure selector so the same ordering rules can be unit-tested. */
export function selectVisible(state: State): Title[] {
  const query = state.query.trim().toLowerCase();
  let titles = state.titles;

  if (state.selectedCollection) {
    const ids = new Set(state.collections[state.selectedCollection] ?? []);
    titles = titles.filter((title) => ids.has(title.id));
  }

  titles = titles.filter((title) => {
    switch (state.filter) {
      case "movie":
        return title.kind === "movie";
      case "series":
        return title.kind === "series";
      case "unwatched":
        return !title.watched && title.progress === 0;
      case "inprogress":
        return !title.watched && title.progress > 0;
      case "watched":
        return title.watched;
      default:
        return true;
    }
  });

  if (query) {
    titles = titles.filter((title) => {
      const haystack = [displayTitle(title), title.year?.toString() ?? "", ...title.tags].join(" ").toLowerCase();
      return haystack.includes(query);
    });
  }

  const sorted = [...titles];
  sorted.sort((a, b) => {
    switch (state.sort) {
      case "title":
        return displayTitle(a).localeCompare(displayTitle(b), undefined, { numeric: true });
      case "year":
        return (b.year ?? 0) - (a.year ?? 0);
      case "progress":
        return b.progress - a.progress;
      case "recent":
      default:
        return b.addedAt.localeCompare(a.addedAt);
    }
  });
  return sorted;
}

export function displayTitle(title: Title): string {
  return title.displayName ?? title.name;
}

interface LibraryContextValue {
  state: State;
  dispatch: (action: Action) => void;
  visibleTitles: Title[];
  collections: string[];
  storageOk: boolean;
  addTitles: (titles: Title[]) => void;
  removeTitle: (id: string) => Promise<void>;
  reset: () => Promise<void>;
}

const LibraryContext = createContext<LibraryContextValue | null>(null);

export function LibraryProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(libraryReducer, INITIAL);
  const [storageOk] = useState(() => storageAvailable());
  const hydrated = useRef(false);

  // Load once on mount.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const snapshot = await loadSnapshot();
      if (cancelled) return;
      dispatch({ type: "hydrate", snapshot: snapshot ?? EMPTY_LIBRARY });
      hydrated.current = true;
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Persist after hydration, debounced so dragging the scrubber is not a write storm.
  useEffect(() => {
    if (!hydrated.current) return;
    const timer = setTimeout(() => {
      void saveSnapshot({ titles: state.titles, progress: state.progress, collections: state.collections });
    }, 400);
    return () => clearTimeout(timer);
  }, [state.titles, state.progress, state.collections]);

  const addTitles = useCallback((titles: Title[]) => dispatch({ type: "replaceTitles", titles }), []);

  const removeTitle = useCallback(async (id: string) => {
    dispatch({ type: "removeTitle", id });
  }, []);

  const reset = useCallback(async () => {
    await clearAll();
    dispatch({ type: "reset" });
  }, []);

  const value = useMemo<LibraryContextValue>(
    () => ({
      state,
      dispatch,
      visibleTitles: selectVisible(state),
      collections: Object.keys(state.collections),
      storageOk,
      addTitles,
      removeTitle,
      reset,
    }),
    [state, storageOk, addTitles, removeTitle, reset],
  );

  return <LibraryContext.Provider value={value}>{children}</LibraryContext.Provider>;
}

export function useLibrary(): LibraryContextValue {
  const value = useContext(LibraryContext);
  if (!value) throw new Error("useLibrary must be used inside <LibraryProvider>");
  return value;
}

/** Delete a title's blobs (called only after the user confirms removal). */
export async function purgeTitleBlobs(title: Title): Promise<void> {
  await Promise.all(title.files.map((file) => deleteBlob(file.id)));
}
