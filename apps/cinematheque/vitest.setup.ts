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


// jsdom's Blob implementation is incomplete (no size/text/arrayBuffer), which
// would make storage tests assert against jsdom gaps rather than our code. Give
// it the pieces the app actually uses.
if (typeof Blob !== "undefined") {
  const proto = Blob.prototype as Blob & { size?: number };
  if (typeof proto.arrayBuffer !== "function") {
    Object.defineProperty(Blob.prototype, "arrayBuffer", {
      writable: true,
      value: function arrayBuffer(this: Blob): Promise<ArrayBuffer> {
        return new Promise((resolve) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as ArrayBuffer);
          reader.readAsArrayBuffer(this);
        });
      },
    });
  }
  if (typeof (Blob.prototype as unknown as { text?: unknown }).text !== "function") {
    Object.defineProperty(Blob.prototype, "text", {
      writable: true,
      value: function text(this: Blob): Promise<string> {
        return new Promise((resolve) => {
          const reader = new FileReader();
          reader.onload = () => resolve(String(reader.result ?? ""));
          reader.readAsText(this);
        });
      },
    });
  }
}


/**
 * True when this test environment can round-trip a Blob through IndexedDB.
 * jsdom + fake-indexeddb cannot (the clone comes back as `{}`), so storage tests
 * that specifically assert blob fidelity skip there rather than fail on a
 * harness limitation. Real browsers (and the dev server) do support it.
 */
export const blobStorageSupported = await (async () => {
  try {
    if (typeof indexedDB === "undefined" || typeof Blob === "undefined") return false;
    const db = await new Promise<IDBDatabase | null>((resolve) => {
      const request = indexedDB.open("cinematheque-probe", 1);
      request.onupgradeneeded = () => request.result.createObjectStore("probe", { keyPath: "id" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
    });
    if (!db) return false;
    const blob = new Blob(["x"], { type: "text/plain" });
    await new Promise<void>((resolve) => {
      const transaction = db.transaction("probe", "readwrite");
      transaction.objectStore("probe").put({ id: "k", blob });
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => resolve();
    });
    const read = await new Promise<{ blob?: Blob } | undefined>((resolve) => {
      const request = db.transaction("probe").objectStore("probe").get("k");
      request.onsuccess = () => resolve(request.result as { blob?: Blob } | undefined);
      request.onerror = () => resolve(undefined);
    });
    db.close();
    return read?.blob instanceof Blob;
  } catch {
    return false;
  }
})();
