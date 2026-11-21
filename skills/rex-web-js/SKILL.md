---
name: rex-web-js
description: Static and authorized inspection of web apps, minified JS/TS bundles, source maps, WebAssembly (WASM), and Electron packages.
triggers: javascript, typescript, webpack, vite, bundle, source map, wasm, electron, asar, web app
tools_required: node, python3, rg
---

# REX Web, JavaScript, WASM & Electron Skill

## Supported Targets
Minified JS/TS bundles, `.map` source maps, `.wasm` modules (`00 61 73 6D`), Electron `app.asar` archives, and authorized frontend web assets.

## Headless Workflow
1. **Electron `.asar` Extraction:** Extract safely into workspace (`npx --yes @electron/asar extract`) and inspect `package.json`, `main`, and `preload.js`.
2. **Beautification & Source Maps:** Check `//# sourceMappingURL=` and beautify minified JS (`js-beautify`) into `$WS/generated/`.
3. **API & Dependency Audit:** Inspect `package.json`, lockfiles, `fetch()`/`axios`/WebSocket endpoints, and WASM imports/exports (`r2 -q -c "ii; ie"`).

## Evidence Rules
Separate observed frontend client behavior from unverified server-side assumptions. Redact tokens and API keys.
