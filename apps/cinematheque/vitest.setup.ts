import "@testing-library/jest-dom/vitest";

// jsdom has no media pipeline: make the APIs the app touches harmless stubs so
// tests exercise our logic (not the browser's codec support).
if (!("HTMLMediaElement" in globalThis) || true) {
  const proto = globalThis.HTMLMediaElement?.prototype;
  if (proto) {
    Object.defineProperty(proto, "play", { writable: true, value: () => Promise.resolve() });
    Object.defineProperty(proto, "pause", { writable: true, value: () => undefined });
    Object.defineProperty(proto, "load", { writable: true, value: () => undefined });
  }
}

if (!globalThis.matchMedia) {
  globalThis.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  })) as typeof window.matchMedia;
}

if (!globalThis.URL.createObjectURL) {
  let counter = 0;
  Object.defineProperty(globalThis.URL, "createObjectURL", {
    writable: true,
    value: () => `blob:test/${counter++}`,
  });
  Object.defineProperty(globalThis.URL, "revokeObjectURL", { writable: true, value: () => undefined });
}
