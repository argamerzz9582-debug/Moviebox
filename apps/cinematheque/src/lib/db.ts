/**
 * IndexedDB persistence (no dependency, no server).
 *
 * Two stores:
 *   - `meta`   : the serialised library snapshot (one record)
 *   - `files`  : the media payloads, keyed by media-file id
 *
 * **Storage strategy matters for playback.** Reading a 2 GB file into an
 * `ArrayBuffer` (then rebuilding a `Blob` from it) allocates the whole film in
 * memory twice, which freezes or crashes the tab — that was the "it gets stuck
 * and never plays" bug. So the payload is stored as a `Blob` whenever the engine
 * can structured-clone one (every current browser can), which lets
 * `URL.createObjectURL` hand the browser a *reference* instead of a copy. The
 * ArrayBuffer form is kept only as a fallback, and remains readable, so
 * libraries created by earlier versions keep working.
 */
import type { LibrarySnapshot } from "./types";

const DB_NAME = "cinematheque";
const DB_VERSION = 2;
const META_STORE = "meta";
const FILE_STORE = "files";
const SNAPSHOT_KEY = "snapshot";

export interface StoredBlob {
  id: string;
  blob: Blob;
  fileName: string;
}

/** What actually goes on disk. Either field may be present (see header note). */
interface BlobRecord {
  id: string;
  blob?: Blob;
  data?: ArrayBuffer;
  type: string;
  fileName: string;
  /** Bytes, kept so the UI can show sizes without touching the payload. */
  size: number;
}

/** One cached connection: opening a connection per call stalls under load. */
let connection: Promise<IDBDatabase> | null = null;
/** Some engines reject Blob values; remember the first failure and stop trying. */
let preferArrayBuffer = false;

function openDatabase(): Promise<IDBDatabase> {
  if (connection) return connection;
  connection = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB unavailable"));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE);
      if (!db.objectStoreNames.contains(FILE_STORE)) db.createObjectStore(FILE_STORE, { keyPath: "id" });
    };
    request.onsuccess = () => {
      const db = request.result;
      // A second tab upgrading the schema would otherwise block forever.
      db.onversionchange = () => {
        db.close();
        connection = null;
      };
      resolve(db);
    };
    request.onerror = () => {
      connection = null;
      reject(request.error ?? new Error("IndexedDB open failed"));
    };
  });
  return connection;
}

async function tx<T>(
  store: string,
  mode: IDBTransactionMode,
  run: (object: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await openDatabase();
  return new Promise<T>((resolve, reject) => {
    let result: T;
    const transaction = db.transaction(store, mode);
    const request = run(transaction.objectStore(store));
    request.onsuccess = () => {
      result = request.result;
    };
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}

/** True when the browser can persist a library (private windows sometimes cannot). */
export function storageAvailable(): boolean {
  try {
    return typeof indexedDB !== "undefined";
  } catch {
    return false;
  }
}

/**
 * Ask the browser not to evict this origin's data under storage pressure.
 * Returns whether storage is now durable (false is normal on some engines).
 */
export async function requestPersistence(): Promise<boolean> {
  try {
    if (!navigator.storage?.persist) return false;
    if (await navigator.storage.persisted?.()) return true;
    return await navigator.storage.persist();
  } catch {
    return false;
  }
}

export async function isPersisted(): Promise<boolean> {
  try {
    return (await navigator.storage?.persisted?.()) ?? false;
  } catch {
    return false;
  }
}

export async function loadSnapshot(): Promise<LibrarySnapshot | undefined> {
  try {
    const value = await tx<LibrarySnapshot | undefined>(META_STORE, "readonly", (store) => store.get(SNAPSHOT_KEY));
    return value ?? undefined;
  } catch {
    return undefined;
  }
}

export async function saveSnapshot(snapshot: LibrarySnapshot): Promise<void> {
  try {
    await tx(META_STORE, "readwrite", (store) => store.put(snapshot, SNAPSHOT_KEY));
  } catch {
    // Persistence is best-effort: the in-memory library keeps working.
  }
}

/** Read a Blob as bytes, with a FileReader fallback for engines lacking arrayBuffer(). */
async function toArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
  const candidate = blob as Blob & { arrayBuffer?: () => Promise<ArrayBuffer> };
  if (typeof candidate.arrayBuffer === "function") return candidate.arrayBuffer();
  return new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error ?? new Error("could not read blob"));
    reader.readAsArrayBuffer(blob);
  });
}

/**
 * Persist one media payload.
 *
 * Stores the Blob itself when possible (no copy, instant object URLs); falls
 * back to bytes only for engines that refuse Blob values.
 */
export async function putBlob(record: StoredBlob): Promise<void> {
  const base = { id: record.id, type: record.blob.type, fileName: record.fileName, size: record.blob.size };

  if (!preferArrayBuffer) {
    try {
      await tx(FILE_STORE, "readwrite", (store) => store.put({ ...base, blob: record.blob } satisfies BlobRecord));
      return;
    } catch {
      preferArrayBuffer = true;
    }
  }

  const data = await toArrayBuffer(record.blob);
  await tx(FILE_STORE, "readwrite", (store) => store.put({ ...base, data } satisfies BlobRecord));
}

/**
 * Fetch a payload for playback.
 *
 * The returned Blob is a live reference for records stored as Blobs (no read of
 * the whole file), and a lazily-backed Blob for the ArrayBuffer fallback.
 */
export async function getBlob(id: string): Promise<StoredBlob | undefined> {
  try {
    const record = await tx<BlobRecord | undefined>(FILE_STORE, "readonly", (store) => store.get(id));
    if (!record) return undefined;
    if (record.blob) return { id: record.id, fileName: record.fileName, blob: record.blob };
    if (record.data) {
      return { id: record.id, fileName: record.fileName, blob: new Blob([record.data], { type: record.type }) };
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** Cheap existence check that never materialises the payload. */
export async function hasBlob(id: string): Promise<boolean> {
  try {
    const key = await tx<IDBValidKey | undefined>(FILE_STORE, "readonly", (store) => store.getKey(id));
    return key !== undefined;
  } catch {
    return false;
  }
}

export async function deleteBlob(id: string): Promise<void> {
  try {
    await tx(FILE_STORE, "readwrite", (store) => store.delete(id));
  } catch {
    // ignore: a missing blob is equivalent to a deleted one
  }
}

/** Wipe both stores (used by "Reset library"). */
export async function clearAll(): Promise<void> {
  await tx(META_STORE, "readwrite", (store) => store.clear()).catch(() => undefined);
  await tx(FILE_STORE, "readwrite", (store) => store.clear()).catch(() => undefined);
}

/** Storage pressure estimate, when the browser exposes it. */
export async function storageEstimate(): Promise<{ usage: number; quota: number } | undefined> {
  const storage = navigator.storage;
  if (!storage?.estimate) return undefined;
  try {
    const estimate = await storage.estimate();
    return { usage: estimate.usage ?? 0, quota: estimate.quota ?? 0 };
  } catch {
    return undefined;
  }
}
