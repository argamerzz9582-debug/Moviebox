/**
 * Library state tests: the reducer is where all library rules live, so it is
 * tested directly (no React) plus one integration test through the UI.
 */
import { describe, expect, it } from "vitest";
import { libraryReducer, selectVisible, WATCHED_THRESHOLD, type SortKey } from "../src/state/library";
import { EMPTY_LIBRARY, type Title } from "../src/lib/types";

function makeTitle(overrides: Partial<Title> = {}): Title {
  return {
    id: "t1",
    kind: "movie",
    name: "Arrival",
    year: 2016,
    tags: ["1080p"],
    addedAt: "2024-01-01T00:00:00.000Z",
    progress: 0,
    watched: false,
    files: [{ id: "f1", titleId: "t1", fileName: "Arrival.2016.1080p.mkv", size: 1000, duration: 6000, mime: "video/mp4" }],
    ...overrides,
  };
}

const base = { ...EMPTY_LIBRARY, status: "ready" as const, sort: "recent" as SortKey, filter: "all" as const, query: "", selectedCollection: null };

describe("libraryReducer", () => {
  it("hydrates without dropping UI state", () => {
    const state = libraryReducer({ ...base, query: "arr" }, { type: "hydrate", snapshot: { titles: [makeTitle()], progress: {}, collections: {} } });
    expect(state.titles).toHaveLength(1);
    expect(state.query).toBe("arr");
    expect(state.status).toBe("ready");
  });

  it("removes a title and its progress + collection memberships", () => {
    const state = libraryReducer(
      { ...base, titles: [makeTitle()], progress: { t1: { titleId: "t1", seconds: 10, duration: 100, updatedAt: "x" } }, collections: { Faves: ["t1", "t2"] } },
      { type: "removeTitle", id: "t1" },
    );
    expect(state.titles).toHaveLength(0);
    expect(state.progress.t1).toBeUndefined();
    expect(state.collections.Faves).toEqual(["t2"]);
  });

  it("renames via displayName and rejects a blank rename", () => {
    const withName = libraryReducer({ ...base, titles: [makeTitle()] }, { type: "renameTitle", id: "t1", name: "  Arrival (2016) " });
    expect(withName.titles[0]?.displayName).toBe("Arrival (2016)");
    const cleared = libraryReducer(withName, { type: "renameTitle", id: "t1", name: "   " });
    expect(cleared.titles[0]?.displayName).toBeUndefined();
  });

  it("marks a title watched once progress crosses the threshold", () => {
    const state = libraryReducer(
      { ...base, titles: [makeTitle()] },
      { type: "setProgress", record: { titleId: "t1", seconds: 6000 * WATCHED_THRESHOLD, duration: 6000, updatedAt: "x" } },
    );
    expect(state.titles[0]?.watched).toBe(true);
    expect(state.progress.t1?.seconds).toBe(6000 * WATCHED_THRESHOLD);
  });

  it("does not un-watch a finished title by rewinding", () => {
    const state = libraryReducer(
      { ...base, titles: [makeTitle({ watched: true })] },
      { type: "setProgress", record: { titleId: "t1", seconds: 5, duration: 6000, updatedAt: "x" } },
    );
    expect(state.titles[0]?.watched).toBe(true);
  });

  it("toggles watched explicitly", () => {
    const state = libraryReducer({ ...base, titles: [makeTitle()] }, { type: "toggleWatched", id: "t1" });
    expect(state.titles[0]?.watched).toBe(true);
  });

  it("creates collections, ignores duplicates and blanks", () => {
    let state = libraryReducer(base, { type: "createCollection", name: "Sci-fi" });
    state = libraryReducer(state, { type: "createCollection", name: "Sci-fi" });
    state = libraryReducer(state, { type: "createCollection", name: "   " });
    expect(Object.keys(state.collections)).toEqual(["Sci-fi"]);
  });

  it("toggles a title in and out of a collection", () => {
    let state = libraryReducer(base, { type: "createCollection", name: "Faves" });
    state = libraryReducer(state, { type: "toggleInCollection", collection: "Faves", titleId: "t1" });
    expect(state.collections.Faves).toEqual(["t1"]);
    state = libraryReducer(state, { type: "toggleInCollection", collection: "Faves", titleId: "t1" });
    expect(state.collections.Faves).toEqual([]);
  });

  it("clears the collection selection when the collection is deleted", () => {
    let state = libraryReducer(base, { type: "createCollection", name: "Faves" });
    state = libraryReducer(state, { type: "selectCollection", name: "Faves" });
    state = libraryReducer(state, { type: "deleteCollection", collection: "Faves" });
    expect(state.selectedCollection).toBeNull();
    expect(state.collections.Faves).toBeUndefined();
  });

  it("resets everything", () => {
    const state = libraryReducer({ ...base, titles: [makeTitle()], query: "x" }, { type: "reset" });
    expect(state.titles).toEqual([]);
    expect(state.query).toBe("");
  });
});

describe("selectVisible", () => {
  const titles = [
    makeTitle({ id: "a", name: "Arrival", year: 2016, kind: "movie", addedAt: "2024-01-01T00:00:00.000Z" }),
    makeTitle({ id: "b", name: "The Bear", year: 2022, kind: "series", addedAt: "2024-03-01T00:00:00.000Z", progress: 30 }),
    makeTitle({ id: "c", name: "Chernobyl", year: 2019, kind: "series", addedAt: "2024-02-01T00:00:00.000Z", watched: true, progress: 600 }),
  ];
  const state = { ...base, titles };

  it("sorts by recency by default", () => {
    expect(selectVisible(state).map((t) => t.id)).toEqual(["b", "c", "a"]);
  });

  it("sorts alphabetically ignoring articles is not required, but numeric-aware is", () => {
    expect(selectVisible({ ...state, sort: "title" }).map((t) => t.name)).toEqual(["Arrival", "Chernobyl", "The Bear"]);
  });

  it("sorts by year descending", () => {
    expect(selectVisible({ ...state, sort: "year" }).map((t) => t.id)).toEqual(["b", "c", "a"]);
  });

  it("filters by kind", () => {
    expect(selectVisible({ ...state, filter: "series" }).map((t) => t.id)).toEqual(["b", "c"]);
    expect(selectVisible({ ...state, filter: "movie" }).map((t) => t.id)).toEqual(["a"]);
  });

  it("distinguishes in-progress from not-started and watched", () => {
    expect(selectVisible({ ...state, filter: "inprogress" }).map((t) => t.id)).toEqual(["b"]);
    expect(selectVisible({ ...state, filter: "unwatched" }).map((t) => t.id)).toEqual(["a"]);
    expect(selectVisible({ ...state, filter: "watched" }).map((t) => t.id)).toEqual(["c"]);
  });

  it("searches name, year and tags", () => {
    expect(selectVisible({ ...state, query: "bear" }).map((t) => t.id)).toEqual(["b"]);
    expect(selectVisible({ ...state, query: "2019" }).map((t) => t.id)).toEqual(["c"]);
    expect(selectVisible({ ...state, query: "1080p" })).toHaveLength(3);
  });

  it("intersects a collection with the filter and search", () => {
    const withCollection = { ...state, collections: { Mine: ["a", "c"] }, selectedCollection: "Mine" };
    expect(selectVisible(withCollection).map((t) => t.id)).toEqual(["c", "a"]);
    expect(selectVisible({ ...withCollection, filter: "movie" }).map((t) => t.id)).toEqual(["a"]);
    expect(selectVisible({ ...withCollection, query: "nope" })).toHaveLength(0);
  });

  it("does not mutate the input array", () => {
    const before = titles.map((t) => t.id);
    selectVisible({ ...state, sort: "title" });
    expect(titles.map((t) => t.id)).toEqual(before);
  });
});
