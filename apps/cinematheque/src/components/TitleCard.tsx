import { IconCheck, IconStar } from "./icons";
import { Poster } from "./Poster";
import { displayTitle, useLibrary } from "../state/library";
import { formatDuration, progressFraction } from "../lib/parse";
import type { Title } from "../lib/types";

interface TitleCardProps {
  title: Title;
  onOpen: (title: Title) => void;
}

export function TitleCard({ title, onOpen }: TitleCardProps) {
  const { dispatch } = useLibrary();
  const name = displayTitle(title);
  const duration = title.files[0]?.duration ?? 0;
  const fraction = progressFraction(title.progress, duration);

  const meta: string[] = [];
  if (title.year) meta.push(String(title.year));
  if (title.kind === "series") meta.push(`${title.files.length} ep`);
  else if (duration > 0) meta.push(formatDuration(duration));

  return (
    <div className="card">
      <button
        className="card__poster-button"
        onClick={() => onOpen(title)}
        aria-label={`Open ${name}`}
        style={{ all: "unset", cursor: "pointer", display: "block", position: "relative" }}
      >
        <Poster name={name}>
          {title.kind === "series" && <span className="card__badge">Series</span>}
          {title.favourite && (
            <span className="card__star">
              <IconStar width={15} height={15} />
            </span>
          )}
          {fraction > 0 && !title.watched && (
            <span className="card__resume">
              <span style={{ width: `${Math.max(2, fraction * 100)}%` }} />
            </span>
          )}
        </Poster>
      </button>

      {/* Quick actions live outside the open-button: nested buttons are invalid HTML. */}
      <div className="card__quick">
        <button
          aria-pressed={Boolean(title.favourite)}
          aria-label={title.favourite ? `Unfavourite ${name}` : `Favourite ${name}`}
          title="Favourite"
          onClick={() => dispatch({ type: "toggleFavourite", id: title.id })}
        >
          <IconStar width={14} height={14} />
        </button>
        <button
          aria-pressed={title.watched}
          aria-label={title.watched ? `Mark ${name} unwatched` : `Mark ${name} watched`}
          title="Watched"
          onClick={() => dispatch({ type: "toggleWatched", id: title.id })}
        >
          <IconCheck width={14} height={14} />
        </button>
      </div>

      <button className="card__title-button" onClick={() => onOpen(title)} style={{ all: "unset", cursor: "pointer" }}>
        <span className="card__title">{name}</span>
        <span className="card__meta">
          {title.watched && <IconCheck width={13} height={13} className="card__watched" />}
          {meta.join(" · ")}
          {fraction > 0 && !title.watched && ` · ${Math.round(fraction * 100)}%`}
        </span>
      </button>
    </div>
  );
}

/** Dense list row — the alternative to the poster grid on big libraries. */
export function TitleRow({ title, onOpen }: TitleCardProps) {
  const { dispatch } = useLibrary();
  const name = displayTitle(title);
  const duration = title.files[0]?.duration ?? 0;
  const fraction = progressFraction(title.progress, duration);

  return (
    <div className="row">
      <button
        onClick={() => onOpen(title)}
        aria-label={`Open ${name}`}
        style={{ all: "unset", cursor: "pointer", display: "contents" }}
      >
        <Poster name={name} className="row__art" />
        <span style={{ minWidth: 0, display: "block" }}>
          <span className="row__name" style={{ display: "block" }}>
            {title.favourite ? "★ " : ""}
            {name}
          </span>
          <span className="row__meta">
            {[
              title.year,
              title.kind === "series" ? `${title.files.length} ep` : formatDuration(duration),
              title.watched ? "watched" : fraction > 0 ? `${Math.round(fraction * 100)}%` : null,
            ]
              .filter(Boolean)
              .join(" · ")}
          </span>
        </span>
      </button>
      <span className="row__progress" aria-hidden="true">
        <span style={{ width: `${title.watched ? 100 : fraction * 100}%` }} />
      </span>
      <button
        className="btn btn--ghost btn--icon"
        aria-label={title.favourite ? `Unfavourite ${name}` : `Favourite ${name}`}
        aria-pressed={Boolean(title.favourite)}
        onClick={() => dispatch({ type: "toggleFavourite", id: title.id })}
      >
        <IconStar width={15} height={15} />
      </button>
    </div>
  );
}
