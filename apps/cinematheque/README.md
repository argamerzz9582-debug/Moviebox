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
| **Library** | One card per title; episodes of one show collapse into a single series entry. Generated gradient posters (deterministic per title) — no artwork needed, no network call. Grid **or** dense list view, favourites, quick watched toggle, storage meter. |
| **Finding things** | Search across titles/years/tags, sort by recency/title/year/progress, filters (movies, series, continue, finished), and named collections. |
| **Playback (v2)** | Native `<video>`: resume where you left off, auto-advance to the next episode, "Start over", keyboard control (`space` `←` `→` `↑` `↓` `f` `m` `esc`), fullscreen, buffered-range indicator. |
| **Persistence** | IndexedDB. Metadata and payloads live in separate stores, so progress ticks never rewrite gigabytes. Payloads are stored as **Blobs**, not copies, so opening a 4 GB file is instant. |
| **Resilience** | Storage persistence requested on first import; auto-reconnect for a closed connection; stall watchdog; explicit errors for missing payload, zero-byte file and unsupported codec. |
| **PWA** | Installable (manifest + maskable icon), dark `theme-color`, `standalone` display. |

Everything is client-side. There is no backend, no analytics, and no third-party request at
runtime; the only dependency shipped to the browser is `jszip`, loaded **only** when you drop an
archive.

## Deployed

| | |
| --- | --- |
| **Live** | <https://cinematheque-chi.vercel.app> |
| **Vercel project** | `cinematheque` (`prj_c4iACoFBXCONApwEKrsCYwx0a6qI`, team `argamerzz9582-debugs-projects`) |
| **Framework** | Vite (static output, no server functions) |
| **Root directory** | `apps/cinematheque` — required, this repo is a monorepo |
| **Protection** | None on the production alias; it is publicly reachable |

Notes for redeploys: the deployment is a plain static Vite build (`npm run build` → `dist/`).
Vercel's automatic/per-deployment URLs (`cinematheque-<hash>-…vercel.app`) inherit the
team's **Deployment Protection** and will ask for a Vercel login — the stable production
alias above is the one to share.

## Fixes in this pass (the "stuck / never plays" bugs)

Two real defects, both found by reading the code rather than the UI:

1. **Every playback pull copied the whole film into memory.** The payload was
   stored as an `ArrayBuffer`, and `getBlob` rebuilt a `Blob` from it on every
   open — two full-size allocations for a 2 GB file. The tab locks up, the
   spinner never resolves, playback never starts. Payloads are now stored as
   `Blob`s (a reference, not a copy), with the old ArrayBuffer format still
   readable so existing libraries keep working. `hasBlob` now checks existence
   without reading bytes at all.
2. **A blocked autoplay left a black rectangle.** `video.play()` rejects with
   `NotAllowedError` when there is no user gesture; the old code ignored the
   promise, so the UI looked frozen. There is now a large play affordance, a
   retry on click, a stall watchdog with a spinner after 12 s, and distinct
   messages for a missing payload, a zero-byte file and an unsupported codec
   (with "next episode" offered inline).

Also fixed while in there: `Ctrl`/`Cmd`+`O` was advertised in the empty state but
never implemented (it now opens the picker); drag-and-drop was registered twice
(once in the import bar, once nowhere else); and the IndexedDB connection was
re-opened per call and never survived a schema upgrade from another tab.

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
