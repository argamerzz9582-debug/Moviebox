import { useState } from "react";
import { useLibrary } from "../state/library";
import { IconClose, IconPlus, IconTrash } from "./icons";

export function CollectionsDialog({ onClose }: { onClose: () => void }) {
  const { state, dispatch, collections, reset } = useLibrary();
  const [name, setName] = useState("");

  return (
    <div className="dialog-backdrop" onClick={onClose} role="presentation">
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="collections-heading"
        onClick={(event) => event.stopPropagation()}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h2 id="collections-heading">Manage library</h2>
          <button className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close">
            <IconClose />
          </button>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!name.trim()) return;
            dispatch({ type: "createCollection", name });
            setName("");
          }}
          style={{ display: "flex", gap: 8, marginBottom: 14 }}
        >
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="New collection name"
            aria-label="New collection name"
            style={{
              flex: 1,
              padding: "8px 12px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--line)",
              background: "var(--bg)",
            }}
          />
          <button className="btn btn--primary" type="submit">
            <IconPlus width={16} height={16} />
            Create
          </button>
        </form>

        {collections.length === 0 ? (
          <p style={{ color: "var(--ink-muted)" }}>No collections yet. Collections group titles across your folders.</p>
        ) : (
          collections.map((collection) => (
            <div className="dialog__row" key={collection}>
              <span>
                {collection}
                <span style={{ color: "var(--ink-faint)", marginLeft: 8, fontSize: "var(--step--1)" }}>
                  {(state.collections[collection] ?? []).length} titles
                </span>
              </span>
              <button
                className="btn btn--ghost btn--icon"
                aria-label={`Delete ${collection}`}
                onClick={() => dispatch({ type: "deleteCollection", collection })}
              >
                <IconTrash width={16} height={16} />
              </button>
            </div>
          ))
        )}

        <div className="dialog__row" style={{ marginTop: 18, borderTop: "1px solid var(--line)" }}>
          <span>
            Reset everything
            <span style={{ display: "block", color: "var(--ink-faint)", fontSize: "var(--step--1)" }}>
              Removes all titles, progress and stored files from this device.
            </span>
          </span>
          <button
            className="btn btn--danger"
            onClick={async () => {
              if (!window.confirm("Delete the whole library from this device? This cannot be undone.")) return;
              await reset();
              onClose();
            }}
          >
            Reset
          </button>
        </div>
      </div>
    </div>
  );
}
