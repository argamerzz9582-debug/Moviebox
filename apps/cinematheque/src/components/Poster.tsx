/**
 * Generated poster art.
 *
 * The library has no artwork and no network fetches, so each title gets a
 * deterministic gradient derived from its name — stable across reloads, always
 * distinct, and never a blank grey box.
 */
import { useMemo } from "react";

export function gradientFor(seed: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  const hue = Math.abs(hash) % 360;
  const second = (hue + 42 + (Math.abs(hash >> 8) % 60)) % 360;
  return `linear-gradient(155deg, hsl(${hue} 42% 22%), hsl(${second} 48% 12%) 62%, #0b0c10)`;
}

/** First meaningful glyph of a title, skipping articles so "The Bear" -> "B". */
export function monogram(name: string): string {
  const cleaned = name.replace(/^(the|a|an)\s+/i, "").trim();
  return (cleaned[0] ?? name[0] ?? "?").toUpperCase();
}

interface PosterProps {
  name: string;
  className?: string;
  children?: React.ReactNode;
}

export function Poster({ name, className = "card__poster", children }: PosterProps) {
  const background = useMemo(() => gradientFor(name), [name]);
  return (
    <div className={className} style={{ background }} aria-hidden="true">
      <span className="card__monogram">{monogram(name)}</span>
      {children}
    </div>
  );
}
