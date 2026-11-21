# Cinémathèque

A **local-first personal media library** for the web — a redesign built from scratch.

Add your own video files (a folder, a season pack, or a single file). Cinémathèque parses the
file names, stores the library on your device, and plays everything in the browser. No account,
no server, no upload, no remote metadata.

> **Why this exists.** The starting point was a review of a modded MovieBox build
> (`reverse-engineering/moviebox-v4.0.04/`). The useful part of that app is the *shape* of the
> experience — a poster grid, instant resume, next-episode flow. The rest (a packed binary
> talking to a copyrighted streaming backend) is not something to copy. This app keeps the
> shape and drops the rest: it only ever plays files **you** already own.

---

## What it does

| Area | Behaviour |
| --- | --- |
| **Import** | Folder picker (File System Access API), multi-file picker, drag-and-drop anywhere, and `.zip` season packs. Walks sub-folders recursively. |
| **Parsing** | Scene-release aware: `The.Bear.S02E05.1080p.WEB-DL.AAC.mkv` → show *The Bear*, S02E05, tags `1080p/web-dl/aac`. Strips release groups, bracketed tags, language suffixes. |
| **Library** | One card per title; episodes of one show collapse into a single series entry. Generated gradient posters (deterministic per title) — no artwork needed, no network call. |
| **Finding things** | Search across titles/years/tags, sort by recency/title/year/progress, filters (movies, series, continue, finished), and named collections. |
| **Playback** | Native `<video>`: resume where you left off, auto-advance to the next episode, "Start over", keyboard control (`space` `←` `→` `↑` `↓` `f` `m` `esc`), fullscreen, buffered-range indicator. |
| **Persistence** | IndexedDB. Metadata and media bytes live in separate stores, so progress ticks never rewrite gigabytes. Verifies the blob still exists before playback and says so if it does not. |
| **PWA** | Installable (manifest + maskable icon), dark `theme-color`, `standalone` display. |

Everything is client-side. There is no backend, no analytics, and no third-party request at
runtime; the only dependency shipped to the browser is `jszip`, loaded **only** when you drop an
archive.

## Run it

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # 62 tests
npm run build    # typecheck + production bundle in dist/
```

## Design notes

- **No router, no state library.** The whole app is one reducer (`src/state/library.tsx`) plus
  three overlays. Navigation is a filter in state, which keeps back/forward predictable and the
  bundle at ~58 KB gzipped (excluding the lazy zip path).
- **Parsing is pure and tested.** `src/lib/parse.ts` has no DOM dependency, so the messy cases
  (season packs, multi-language suffixes, names that are *only* technical tokens) are covered by
  unit tests rather than discovered in production.
- **Blobs are stored as `ArrayBuffer`.** A few engines fail to structured-clone `Blob` into
  IndexedDB; reconstructing on read costs nothing and removes a whole class of platform bugs.
- **The probe is injectable.** Reading duration needs a `<video>` element; `importFiles` takes
  the prober as an option so tests (and a future native/ffprobe path) do not need a media
  pipeline.
- **Honest failures.** Unknown format → a message, not a spinner. Missing blob → "re-import it".
  Storage unavailable (private window) → a banner saying the library will not persist.

## Layout

```
src/
  lib/         parse · importer · db · zip · types   (no React, all unit-tested)
  state/       library.tsx                            (reducer + context + selectors)
  components/  Player · TitleSheet · TitleCard · ImportBar · Sidebar · CollectionsDialog
  screens/     Library.tsx
  styles/      tokens.css (design tokens) · app.css (layout + components)
tests/         parse · library-state · importer · db · app (integration)
```

## Scope and limits

- **Chrome/Edge** get the folder picker; Safari/Firefox fall back to a multi-file input (the
  button label changes to match).
- **Playable formats are the browser's**, not ours: MP4/H.264 is universal, MKV/HEVC support
  varies by platform. An unplayable file still imports and is reported clearly on play.
- Storage is browser-managed and can be evicted under pressure; treat the library as a cache of
  files you still have.
- No transcoding, no subtitles sidecar handling yet, no cast/AirPlay — all deliberate omissions
  for a first version.
