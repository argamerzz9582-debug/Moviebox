/**
 * Video player.
 *
 * Uses the native <video> element (hardware decoding, HDR, captions for free)
 * instead of a canvas/JS pipeline. What we add is the library behaviour the OS
 * player does not know about:
 *
 *   - resume from the stored progress, with a "Start over" affordance
 *   - persist progress on pause/unmount/seek (throttled), never on every tick
 *   - auto-advance to the next episode of a series
 *   - keyboard control (space, arrows, f, m, esc)
 *   - controls that fade out while playing
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getBlob } from "../lib/db";
import { formatDuration, progressFraction } from "../lib/parse";
import { displayTitle, useLibrary } from "../state/library";
import type { MediaFile, Title } from "../lib/types";
import {
  IconBack,
  IconFullscreen,
  IconMuted,
  IconPause,
  IconPlay,
  IconSkip,
  IconVolume,
} from "./icons";

interface PlayerProps {
  title: Title;
  fileId: string;
  onClose: () => void;
  onPlayFile: (fileId: string) => void;
}

const SAVE_EVERY_SECONDS = 5;
const IDLE_MS = 2600;

export function Player({ title, fileId, onClose, onPlayFile }: PlayerProps) {
  const { state, dispatch } = useLibrary();
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const stageRef = useRef<HTMLDivElement | null>(null);
  const idleTimer = useRef<number | undefined>(undefined);
  const lastSaved = useRef(0);

  const [source, setSource] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState(false);
  const [current, setCurrent] = useState(0);
  const [duration, setDuration] = useState(0);
  const [buffered, setBuffered] = useState(0);
  const [muted, setMuted] = useState(false);
  const [volume, setVolume] = useState(1);
  const [idle, setIdle] = useState(false);
  const [showStartOver, setShowStartOver] = useState(false);

  const file = useMemo(
    () => title.files.find((candidate) => candidate.id === fileId) ?? title.files[0],
    [title, fileId],
  );
  const fileIndex = useMemo(() => title.files.findIndex((candidate) => candidate.id === file?.id), [title, file]);
  const nextFile: MediaFile | undefined = title.files[fileIndex + 1];

  // Resolve the blob into an object URL, and revoke it on change/unmount.
  useEffect(() => {
    let url: string | null = null;
    let cancelled = false;
    setSource(null);
    setError(null);

    if (!file) {
      setError("This title has no playable file.");
      return;
    }

    (async () => {
      const stored = await getBlob(file.id);
      if (cancelled) return;
      if (!stored) {
        setError("The video file is no longer on this device. Re-import it to play.");
        return;
      }
      url = URL.createObjectURL(stored.blob);
      setSource(url);
    })();

    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [file]);

  const persist = useCallback(
    (seconds: number, total: number) => {
      if (!file || !Number.isFinite(seconds)) return;
      if (Math.abs(seconds - lastSaved.current) < SAVE_EVERY_SECONDS && seconds < total - 1) return;
      lastSaved.current = seconds;
      dispatch({
        type: "setProgress",
        record: {
          titleId: title.id,
          seconds,
          duration: total || file.duration,
          updatedAt: new Date().toISOString(),
        },
      });
    },
    [dispatch, file, title.id],
  );

  // Apply saved resume position once metadata is available.
  const applyResume = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    const total = video.duration || 0;
    setDuration(total);
    const saved = state.progress[title.id]?.seconds ?? title.progress ?? 0;
    const fraction = progressFraction(saved, total);
    if (saved > 5 && fraction < 0.95) {
      video.currentTime = saved;
      lastSaved.current = saved;
      setShowStartOver(true);
    }
  }, [state.progress, title.id, title.progress]);

  // Keyboard shortcuts.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const video = videoRef.current;
      if (!video) return;
      switch (event.key) {
        case " ":
        case "k":
          event.preventDefault();
          void (video.paused ? video.play() : video.pause());
          break;
        case "ArrowRight":
          video.currentTime = Math.min(video.duration || Infinity, video.currentTime + 10);
          break;
        case "ArrowLeft":
          video.currentTime = Math.max(0, video.currentTime - 10);
          break;
        case "ArrowUp":
          setVolume((v) => Math.min(1, Number((v + 0.1).toFixed(2))));
          break;
        case "ArrowDown":
          setVolume((v) => Math.max(0, Number((v - 0.1).toFixed(2))));
          break;
        case "m":
          setMuted((m) => !m);
          break;
        case "f":
          void toggleFullscreen();
          break;
        case "Escape":
          if (document.fullscreenElement) void document.exitFullscreen();
          else onClose();
          break;
        default:
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Keep the volume element in sync with state.
  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.volume = volume;
      videoRef.current.muted = muted;
    }
  }, [volume, muted]);

  // Persist the final position when the player unmounts (title change/close).
  useEffect(() => {
    return () => {
      const video = videoRef.current;
      if (video && Number.isFinite(video.currentTime)) {
        persist(video.currentTime, video.duration || 0);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file?.id]);

  const nudgeIdle = useCallback(() => {
    setIdle(false);
    window.clearTimeout(idleTimer.current);
    idleTimer.current = window.setTimeout(() => {
      if (!videoRef.current?.paused) setIdle(true);
    }, IDLE_MS);
  }, []);

  useEffect(() => () => window.clearTimeout(idleTimer.current), []);

  async function toggleFullscreen() {
    const stage = stageRef.current;
    if (!stage) return;
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await stage.requestFullscreen();
    } catch {
      // Fullscreen can be blocked by the embedding frame; playback still works.
    }
  }

  function seekToFraction(fraction: number) {
    const video = videoRef.current;
    if (!video?.duration) return;
    video.currentTime = Math.max(0, Math.min(video.duration, fraction * video.duration));
  }

  const name = displayTitle(title);
  const total = duration || file?.duration || 0;

  return (
    <div className="player" data-idle={idle} onMouseMove={nudgeIdle} onTouchStart={nudgeIdle}>
      <div className="player__stage" ref={stageRef}>
        {source && (
          <video
            ref={videoRef}
            className="player__video"
            src={source}
            autoPlay
            playsInline
            controls={false}
            onClick={() => {
              const video = videoRef.current;
              if (!video) return;
              void (video.paused ? video.play() : video.pause());
            }}
            onLoadedMetadata={applyResume}
            onPlay={() => {
              setPlaying(true);
              nudgeIdle();
            }}
            onPause={() => {
              setPlaying(false);
              setIdle(false);
              const video = videoRef.current;
              if (video) persist(video.currentTime, video.duration || 0);
            }}
            onTimeUpdate={(event) => {
              const video = event.currentTarget;
              setCurrent(video.currentTime);
              if (video.buffered.length) {
                setBuffered(video.buffered.end(video.buffered.length - 1));
              }
              persist(video.currentTime, video.duration || 0);
            }}
            onEnded={() => {
              const video = videoRef.current;
              if (video) persist(video.duration || 0, video.duration || 0);
              if (nextFile) onPlayFile(nextFile.id);
            }}
            onError={() => setError("This file format cannot be played in this browser.")}
          />
        )}

        {error && (
          <div style={{ padding: 24, textAlign: "center", color: "var(--ink-muted)" }}>
            <p style={{ marginBottom: 12 }}>{error}</p>
            <button className="btn" onClick={onClose}>
              Back to library
            </button>
          </div>
        )}

        <div className="player__topbar">
          <button className="btn btn--ghost btn--icon" onClick={onClose} aria-label="Close player">
            <IconBack />
          </button>
          <span className="player__title">
            {name}
            {title.kind === "series" && file && ` · ${episodeLabel(file)}`}
          </span>
        </div>

        {nextFile && (
          <button className="player__skip" onClick={() => onPlayFile(nextFile.id)}>
            <IconSkip width={16} height={16} style={{ verticalAlign: "-2px", marginRight: 6 }} />
            Next episode
          </button>
        )}

        <div className="player__controls">
          <div
            className="player__scrub"
            role="slider"
            tabIndex={0}
            aria-label="Seek"
            aria-valuemin={0}
            aria-valuemax={Math.round(total)}
            aria-valuenow={Math.round(current)}
            onClick={(event) => {
              const rect = event.currentTarget.getBoundingClientRect();
              seekToFraction((event.clientX - rect.left) / rect.width);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowRight") seekToFraction((current + 10) / (total || 1));
              if (event.key === "ArrowLeft") seekToFraction((current - 10) / (total || 1));
            }}
          >
            <div className="player__scrub-track">
              <div
                className="player__scrub-fill"
                style={{ width: `${progressFraction(current, total) * 100}%` }}
              />
            </div>
            {buffered > 0 && (
              <div className="player__scrub-track" style={{ opacity: 0.5, marginTop: -4 }}>
                <div className="player__scrub-buffer" style={{ width: `${progressFraction(buffered, total) * 100}%` }} />
              </div>
            )}
          </div>

          <div className="player__row">
            <button
              className="btn btn--ghost btn--icon"
              aria-label={playing ? "Pause" : "Play"}
              onClick={() => {
                const video = videoRef.current;
                if (!video) return;
                void (video.paused ? video.play() : video.pause());
              }}
            >
              {playing ? <IconPause width={22} height={22} /> : <IconPlay width={22} height={22} />}
            </button>

            <span className="player__time">
              {clock(current)} / {clock(total)}
            </span>

            {showStartOver && (
              <button
                className="btn btn--ghost"
                onClick={() => {
                  if (videoRef.current) videoRef.current.currentTime = 0;
                  setShowStartOver(false);
                }}
              >
                Start over
              </button>
            )}

            <span className="player__spacer" />

            <button
              className="btn btn--ghost btn--icon"
              aria-label={muted ? "Unmute" : "Mute"}
              onClick={() => setMuted((value) => !value)}
            >
              {muted || volume === 0 ? <IconMuted width={20} height={20} /> : <IconVolume width={20} height={20} />}
            </button>

            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={muted ? 0 : volume}
              aria-label="Volume"
              style={{ width: 84 }}
              onChange={(event) => {
                setVolume(Number(event.target.value));
                setMuted(Number(event.target.value) === 0);
              }}
            />

            <button className="btn btn--ghost btn--icon" aria-label="Fullscreen" onClick={() => void toggleFullscreen()}>
              <IconFullscreen width={20} height={20} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function clock(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "0:00";
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const pad = (value: number) => String(value).padStart(2, "0");
  return hours > 0 ? `${hours}:${pad(minutes)}:${pad(secs)}` : `${minutes}:${pad(secs)}`;
}

function episodeLabel(file: MediaFile): string {
  // Imported episodes keep their season/episode in the file name; show the tail.
  const match = /s(\d{1,2})[\s._-]?e(\d{1,3})/i.exec(file.fileName);
  if (match) return `S${match[1]?.padStart(2, "0")}E${match[2]?.padStart(2, "0")}`;
  return formatDuration(file.duration);
}
