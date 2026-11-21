/**
 * IndexedDB persistence (no dependency, no server).
 *
 * Two stores:
 *   - `meta`   : the serialised library snapshot (one record)
 *   - `files`  : the media Blobs, keyed by media-file id
 *
 * Media blobs are stored separately from metadata so a library scan of 200
 * titles does not rewrite 40 GB of video data on every progress tick. Progress
 * updates only touch `meta`. Blobs are persisted as ArrayBuffers rather than
 * Blobs: a few engines (older WebKit) fail to structured-clone Blobs into
 * IndexedDB, and reconstructing on read is cheap.
 */
import type { LibrarySnapshot } from "./types";

const DB_NAME = "cinematheque";
const DB_VERSION = 1;
const META_STORE = "meta";
const FILE_STORE = "files";
const SNAPSHOT_KEY = "snapshot";

export interface StoredBlob {
  id: string;
  blob: Blob;
  fileName: string;
}

/** What actually goes on disk: a Blob is not portable across every engine. */
interface BlobRecord {
  id: string;
  data: ArrayBuffer;
  type: string;
  fileName: string;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
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
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
  });
}

function tx<T>(store: string, mode: IDBTransactionMode, run: (object: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDatabase().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(store, mode);
        const request = run(transaction.objectStore(store));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
        transaction.oncomplete = () => db.close();
      }),
  );
}

/** True when the browser can persist a library (private windows sometimes cannot). */
export function storageAvailable(): boolean {
  try {
    return typeof indexedDB !== "undefined";
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

export async function putBlob(record: StoredBlob): Promise<void> {
  const stored: BlobRecord = {
    id: record.id,
    data: await toArrayBuffer(record.blob),
    type: record.blob.type,
    fileName: record.fileName,
  };
  await tx(FILE_STORE, "readwrite", (store) => store.put(stored));
}

export async function getBlob(id: string): Promise<StoredBlob | undefined> {
  try {
    const record = await tx<BlobRecord | undefined>(FILE_STORE, "readonly", (store) => store.get(id));
    if (!record?.data) return undefined;
    return { id: record.id, fileName: record.fileName, blob: new Blob([record.data], { type: record.type }) };
  } catch {
    return undefined;
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
