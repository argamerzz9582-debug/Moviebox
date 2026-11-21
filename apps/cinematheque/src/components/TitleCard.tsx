import { IconCheck } from "./icons";
import { Poster } from "./Poster";
import { displayTitle } from "../state/library";
import { formatDuration, progressFraction } from "../lib/parse";
import type { Title } from "../lib/types";

interface TitleCardProps {
  title: Title;
  onOpen: (title: Title) => void;
}

export function TitleCard({ title, onOpen }: TitleCardProps) {
  const name = displayTitle(title);
  const duration = title.files[0]?.duration ?? 0;
  const fraction = progressFraction(title.progress, duration);

  const meta: string[] = [];
  if (title.year) meta.push(String(title.year));
  if (title.kind === "series") meta.push(`${title.files.length} ep`);
  else if (duration > 0) meta.push(formatDuration(duration));

  return (
    <button className="card" onClick={() => onOpen(title)} aria-label={`Open ${name}`}>
      <Poster name={name}>
        {title.kind === "series" && <span className="card__badge">Series</span>}
        {fraction > 0 && !title.watched && (
          <span className="card__resume">
            <span style={{ width: `${Math.max(2, fraction * 100)}%` }} />
          </span>
        )}
      </Poster>
      <span className="card__title">{name}</span>
      <span className="card__meta">
        {title.watched && <IconCheck width={13} height={13} className="card__watched" />}
        {meta.join(" · ")}
        {fraction > 0 && !title.watched && ` · ${Math.round(fraction * 100)}%`}
      </span>
    </button>
  );
}
