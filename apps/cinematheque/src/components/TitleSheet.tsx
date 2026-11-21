/**
 * Title detail sheet: play/resume, episode list, rename, collections, remove.
 *
 * Rendered as a bottom sheet on small screens and a centred dialog on desktop
 * (same DOM, CSS decides). Everything the user can do to a title lives here so
 * the grid stays a pure browsing surface.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { formatBytes, formatDuration, progressFraction } from "../lib/parse";
import { displayTitle, purgeTitleBlobs, useLibrary } from "../state/library";
import type { Title } from "../lib/types";
import { IconCheck, IconClose, IconPlay, IconPlus, IconTrash } from "./icons";
import { Poster } from "./Poster";

interface TitleSheetProps {
  title: Title;
  onClose: () => void;
  onPlay: (fileId: string) => void;
}

export function TitleSheet({ title, onClose, onPlay }: TitleSheetProps) {
  const { state, dispatch, collections, removeTitle } = useLibrary();
  const [renaming, setRenaming] = useState(false);
  const [draftName, setDraftName] = useState(displayTitle(title));
  const [newCollection, setNewCollection] = useState("");
  const dialogRef = useRef<HTMLDivElement | null>(null);

  // Focus trap-ish: focus the dialog and close on Escape.
  useEffect(() => {
    dialogRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const record = state.progress[title.id];
  const name = displayTitle(title);
  const resumeAt = record?.seconds ?? title.progress;
  const firstFile = title.files[0];
  const duration = firstFile?.duration ?? record?.duration ?? 0;
  const fraction = progressFraction(resumeAt, duration);

  const totals = useMemo(() => {
    const size = title.files.reduce((sum, file) => sum + file.size, 0);
    const time = title.files.reduce((sum, file) => sum + file.duration, 0);
    return { size, time };
  }, [title.files]);

  return (
    <div className="dialog-backdrop" onClick={onClose} role="presentation">
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="title-sheet-heading"
        tabIndex={-1}
        ref={dialogRef}
        onClick={(event) => event.stopPropagation()}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <h2 id="title-sheet-heading" className="sr-only">
            {name}
          </h2>
          <span />
          <button className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close">
            <IconClose />
          </button>
        </div>

        <div className="detail">
          <div className="detail__head">
            <Poster name={name} className="detail__poster" />
            <div style={{ minWidth: 0, flex: 1 }}>
              {renaming ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    dispatch({ type: "renameTitle", id: title.id, name: draftName });
                    setRenaming(false);
                  }}
                  style={{ display: "flex", gap: 8 }}
                >
                  <input
                    value={draftName}
                    onChange={(event) => setDraftName(event.target.value)}
                    aria-label="Title name"
                    autoFocus
                    style={{
                      flex: 1,
                      padding: "7px 10px",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid var(--line-strong)",
                      background: "var(--bg)",
                    }}
                  />
                  <button className="btn btn--primary" type="submit">
                    Save
                  </button>
                </form>
              ) : (
                <h3 style={{ fontFamily: "var(--font-display)", fontSize: "var(--step-2)", letterSpacing: "-0.02em" }}>
                  {name}
                </h3>
              )}

              <p style={{ color: "var(--ink-muted)", marginTop: 4 }}>
                {[
                  title.year,
                  title.kind === "series" ? `${title.files.length} episode${title.files.length === 1 ? "" : "s"}` : null,
                  totals.size > 0 ? formatBytes(totals.size) : null,
                  title.kind === "series" && totals.time > 0 ? formatDuration(totals.time) : null,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>

              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
                {title.tags.slice(0, 6).map((tag) => (
                  <span className="detail__tag" key={tag}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {fraction > 0 && !title.watched && (
            <div className="progress-pill" style={{ alignSelf: "flex-start" }}>
              <span>Resume at {formatDuration(resumeAt)}</span>
              <span className="progress-pill__track">
                <span className="progress-pill__fill" style={{ width: `${Math.max(3, fraction * 100)}%` }} />
              </span>
            </div>
          )}

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn btn--primary" onClick={() => firstFile && onPlay(firstFile.id)} disabled={!firstFile}>
              <IconPlay width={16} height={16} />
              {resumeAt > 5 && fraction < 0.95 ? "Resume" : "Play"}
            </button>
            <button className="btn" onClick={() => dispatch({ type: "toggleWatched", id: title.id })}>
              <IconCheck width={16} height={16} />
              {title.watched ? "Mark unwatched" : "Mark watched"}
            </button>
            <button className="btn" onClick={() => setRenaming((value) => !value)}>
              Rename
            </button>
            <button
              className="btn btn--danger"
              onClick={async () => {
                if (!window.confirm(`Remove "${name}" and its ${title.files.length} file(s) from this library?`)) return;
                await purgeTitleBlobs(title);
                await removeTitle(title.id);
                onClose();
              }}
            >
              <IconTrash width={16} height={16} />
              Remove
            </button>
          </div>

          <section>
            <h4 style={{ fontSize: "var(--step--1)", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--ink-faint)", marginBottom: 8 }}>
              Collections
            </h4>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {collections.length === 0 && (
                <span style={{ color: "var(--ink-faint)", fontSize: "var(--step--1)" }}>No collections yet.</span>
              )}
              {collections.map((collection) => {
                const active = (state.collections[collection] ?? []).includes(title.id);
                return (
                  <button
                    key={collection}
                    className="chip"
                    aria-pressed={active}
                    onClick={() => dispatch({ type: "toggleInCollection", collection, titleId: title.id })}
                  >
                    {active ? "✓ " : "+ "}
                    {collection}
                  </button>
                );
              })}
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  if (!newCollection.trim()) return;
                  dispatch({ type: "createCollection", name: newCollection });
                  dispatch({ type: "toggleInCollection", collection: newCollection.trim(), titleId: title.id });
                  setNewCollection("");
                }}
                style={{ display: "flex", gap: 6 }}
              >
                <input
                  value={newCollection}
                  onChange={(event) => setNewCollection(event.target.value)}
                  placeholder="New collection"
                  aria-label="New collection name"
                  style={{
                    padding: "6px 10px",
                    borderRadius: "var(--radius-full)",
                    border: "1px solid var(--line)",
                    background: "var(--bg)",
                    width: 132,
                  }}
                />
                <button className="btn btn--icon" type="submit" aria-label="Create collection">
                  <IconPlus />
                </button>
              </form>
            </div>
          </section>

          <section>
            <h4 style={{ fontSize: "var(--step--1)", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--ink-faint)", marginBottom: 8 }}>
              {title.kind === "series" ? "Episodes" : "File"}
            </h4>
            <div className="detail__files">
              {title.files.map((file, index) => (
                <button key={file.id} className="detail__file" onClick={() => onPlay(file.id)}>
                  <span style={{ minWidth: 0 }}>
                    <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {title.kind === "series" ? `${index + 1}. ` : ""}
                      {file.fileName}
                    </span>
                    <span style={{ fontSize: "var(--step--1)", color: "var(--ink-faint)" }}>
                      {[file.quality, formatDuration(file.duration), formatBytes(file.size)].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                  <IconPlay width={16} height={16} />
                </button>
              ))}
            </div>
          </section>

          <p style={{ fontSize: "var(--step--1)", color: "var(--ink-faint)" }}>
            Stored on this device only. Nothing leaves your browser.
          </p>
        </div>
      </div>
    </div>
  );
}
