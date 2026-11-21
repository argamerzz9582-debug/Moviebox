/**
 * Video player.
 *
 * Uses the native <video> element (hardware decoding, HDR, captions for free)
 * instead of a canvas/JS pipeline. What we add is the library behaviour the OS
 * player does not know about:
 *
 *   - resume from stored progress, with "Start over"
 *   - persist progress on pause/seek/close, throttled, never on every tick
 *   - auto-advance to the next episode
 *   - keyboard control (space, arrows, f, m, j/l, esc) and 10s skip buttons
 *   - audible failure states: blocked autoplay, unplayable codec, stall
 *
 * Two fixes over the first version, both about "it never plays":
 *   1. Autoplay is often blocked without a user gesture. Instead of leaving a
 *      black rectangle, a big play affordance appears and playback starts on the
 *      next click/tap.
 *   2. A `stalled`/`waiting` watchdog surfaces a spinner and eventually an
 *      honest message, so a file the browser cannot decode does not look like a
 *      frozen app.
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
  IconPip,
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
const STALL_MS = 12_000;
const VOLUME_KEY = "cinematheque.volume";
const SKIP_SECONDS = 10;

export function Player({ title, fileId, onClose, onPlayFile }: PlayerProps) {
  const { state, dispatch } = useLibrary();
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const stageRef = useRef<HTMLDivElement | null>(null);
  const idleTimer = useRef<number | undefined>(undefined);
  const stallTimer = useRef<number | undefined>(undefined);
  const lastSaved = useRef(0);
  const resumeApplied = useRef(false);

  const [source, setSource] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [autoplayBlocked, setAutoplayBlocked] = useState(false);
  const [stalled, setStalled] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [ready, setReady] = useState(false);
  const [current, setCurrent] = useState(0);
  const [duration, setDuration] = useState(0);
  const [buffered, setBuffered] = useState(0);
  const [muted, setMuted] = useState(false);
  const [volume, setVolume] = useState(() => readStoredVolume());
  const [idle, setIdle] = useState(false);
  const [showStartOver, setShowStartOver] = useState(false);

  const file = useMemo(
    () => title.files.find((candidate) => candidate.id === fileId) ?? title.files[0],
    [title, fileId],
  );
  const fileIndex = useMemo(() => title.files.findIndex((candidate) => candidate.id === file?.id), [title, file]);
  const nextFile: MediaFile | undefined = title.files[fileIndex + 1];

  // Resolve the payload to an object URL. With blob-backed storage this is a
  // reference, not a copy, so opening a 4 GB file is instant.
  useEffect(() => {
    let url: string | null = null;
    let cancelled = false;
    setSource(null);
    setError(null);
    setAutoplayBlocked(false);
    setStalled(false);
    setReady(false);
    resumeApplied.current = false;

    if (!file) {
      setError("This title has no playable file.");
      return;
    }

    (async () => {
      const stored = await getBlob(file.id);
      if (cancelled) return;
      if (!stored || stored.blob.size === 0) {
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

  /** Start playback, surviving a blocked autoplay promise. */
  const startPlayback = useCallback(async () => {
    const video = videoRef.current;
    if (!video) return;
    try {
      await video.play();
      setAutoplayBlocked(false);
    } catch (reason) {
      // NotAllowedError = needs a gesture. Anything else we surface as an error.
      const name = (reason as DOMException)?.name;
      if (name === "NotAllowedError") setAutoplayBlocked(true);
      else if (name !== "AbortError") setError("Playback was blocked. Tap play to try again.");
    }
  }, []);

  // Apply the saved resume position exactly once per file, when metadata lands.
  const applyResume = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    const total = video.duration || 0;
    setDuration(Number.isFinite(total) ? total : 0);
    setReady(true);
    if (resumeApplied.current) return;
    resumeApplied.current = true;
    const saved = state.progress[title.id]?.seconds ?? title.progress ?? 0;
    const fraction = progressFraction(saved, total);
    if (saved > 5 && fraction < 0.95) {
      try {
        video.currentTime = saved;
        lastSaved.current = saved;
        setShowStartOver(true);
      } catch {
        // A seek before the media is seekable throws; playback still starts at 0.
      }
    }
    void startPlayback();
  }, [state.progress, title.id, title.progress, startPlayback]);

  const seekBy = useCallback((delta: number) => {
    const video = videoRef.current;
    if (!video) return;
    const total = Number.isFinite(video.duration) ? video.duration : video.currentTime + Math.abs(delta);
    video.currentTime = Math.max(0, Math.min(total, video.currentTime + delta));
  }, []);

  const togglePlay = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    if (video.paused) void startPlayback();
    else video.pause();
  }, [startPlayback]);

  const toggleFullscreen = useCallback(async () => {
    const stage = stageRef.current;
    if (!stage) return;
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await stage.requestFullscreen();
    } catch {
      // Blocked by the embedding frame; playback is unaffected.
    }
  }, []);

  const togglePip = useCallback(async () => {
    const video = videoRef.current;
    if (!video) return;
    try {
      if (document.pictureInPictureElement) await document.exitPictureInPicture();
      else await video.requestPictureInPicture();
    } catch {
      // Not supported in this browser/context.
    }
  }, []);

  // Keyboard shortcuts.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!videoRef.current) return;
      // Never steal keys from a text field inside the player overlay.
      const target = event.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;

      switch (event.key) {
        case " ":
        case "k":
          event.preventDefault();
          togglePlay();
          break;
        case "ArrowRight":
        case "l":
          event.preventDefault();
          seekBy(SKIP_SECONDS);
          break;
        case "ArrowLeft":
        case "j":
          event.preventDefault();
          seekBy(-SKIP_SECONDS);
          break;
        case "ArrowUp":
          event.preventDefault();
          setVolume((v) => Math.min(1, Number((v + 0.1).toFixed(2))));
          setMuted(false);
          break;
        case "ArrowDown":
          event.preventDefault();
          setVolume((v) => Math.max(0, Number((v - 0.1).toFixed(2))));
          break;
        case "m":
          setMuted((value) => !value);
          break;
        case "f":
          void toggleFullscreen();
          break;
        case "p":
          void togglePip();
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
  }, [onClose, seekBy, togglePip, togglePlay, toggleFullscreen]);

  // Volume + mute are user preferences: persist them across sessions.
  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.volume = volume;
      videoRef.current.muted = muted;
    }
    try {
      localStorage.setItem(VOLUME_KEY, String(volume));
    } catch {
      // storage may be disabled; the in-memory value still works
    }
  }, [volume, muted]);

  // Save the final position when the player closes or the file changes.
  useEffect(() => {
    return () => {
      const video = videoRef.current;
      if (video && Number.isFinite(video.currentTime) && video.currentTime > 0) {
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

  useEffect(
    () => () => {
      window.clearTimeout(idleTimer.current);
      window.clearTimeout(stallTimer.current);
    },
    [],
  );

  /** A stall that never resolves is the difference between "slow" and "broken". */
  const armStallWatchdog = useCallback(() => {
    window.clearTimeout(stallTimer.current);
    stallTimer.current = window.setTimeout(() => setStalled(true), STALL_MS);
  }, []);
  const clearStallWatchdog = useCallback(() => {
    window.clearTimeout(stallTimer.current);
    setStalled(false);
  }, []);

  function seekToFraction(fraction: number) {
    const video = videoRef.current;
    if (!video?.duration) return;
    video.currentTime = Math.max(0, Math.min(video.duration, fraction * video.duration));
  }

  const name = displayTitle(title);
  const total = duration || file?.duration || 0;
  const showBigPlay = !playing && (autoplayBlocked || ready);

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
            preload="metadata"
            controls={false}
            onClick={togglePlay}
            onLoadedMetadata={applyResume}
            onCanPlay={() => {
              setReady(true);
              clearStallWatchdog();
            }}
            onPlay={() => {
              setPlaying(true);
              setAutoplayBlocked(false);
              nudgeIdle();
            }}
            onPause={() => {
              setPlaying(false);
              setIdle(false);
              const video = videoRef.current;
              if (video) persist(video.currentTime, video.duration || 0);
            }}
            onWaiting={() => armStallWatchdog()}
            onPlaying={() => clearStallWatchdog()}
            onSeeking={() => armStallWatchdog()}
            onSeeked={() => clearStallWatchdog()}
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
            onError={() => {
              const code = videoRef.current?.error?.code;
              setError(
                code === 4
                  ? "This file's format or codec is not supported by this browser. Try an MP4 (H.264) copy — the file is still in your library."
                  : "The video could not be loaded. The stored copy may be incomplete — re-import the file.",
              );
            }}
          />
        )}

        {/* Big play affordance: the fix for blocked autoplay / first click. */}
        {showBigPlay && !error && (
          <button className="player__bigplay" onClick={togglePlay} aria-label="Play">
            <IconPlay width={34} height={34} />
          </button>
        )}

        {stalled && !error && (
          <div className="player__status" role="status">
            <span className="spinner" aria-hidden="true" />
            Still preparing… large files can take a moment.
            <button className="btn btn--ghost btn--sm" onClick={() => seekBy(SKIP_SECONDS)}>
              Skip ahead
            </button>
          </div>
        )}

        {error && (
          <div className="player__status player__status--error" role="alert">
            <p>{error}</p>
            <div style={{ display: "flex", gap: 10 }}>
              <button className="btn" onClick={onClose}>
                Back to library
              </button>
              {nextFile && (
                <button className="btn btn--primary" onClick={() => onPlayFile(nextFile.id)}>
                  Next episode
                </button>
              )}
            </div>
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

        {nextFile && !error && (
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
              if (event.key === "ArrowRight") seekToFraction((current + SKIP_SECONDS) / (total || 1));
              if (event.key === "ArrowLeft") seekToFraction((current - SKIP_SECONDS) / (total || 1));
            }}
          >
            <div className="player__scrub-track">
              <div className="player__scrub-fill" style={{ width: `${progressFraction(current, total) * 100}%` }} />
            </div>
            {buffered > 0 && (
              <div className="player__scrub-track" style={{ opacity: 0.5, marginTop: -4 }}>
                <div className="player__scrub-buffer" style={{ width: `${progressFraction(buffered, total) * 100}%` }} />
              </div>
            )}
          </div>

          <div className="player__row">
            <button className="btn btn--ghost btn--icon" aria-label={playing ? "Pause" : "Play"} onClick={togglePlay}>
              {playing ? <IconPause width={22} height={22} /> : <IconPlay width={22} height={22} />}
            </button>

            <button
              className="btn btn--ghost btn--sm"
              onClick={() => seekBy(-SKIP_SECONDS)}
              aria-label={`Back ${SKIP_SECONDS} seconds`}
            >
              −{SKIP_SECONDS}s
            </button>
            <button
              className="btn btn--ghost btn--sm"
              onClick={() => seekBy(SKIP_SECONDS)}
              aria-label={`Forward ${SKIP_SECONDS} seconds`}
            >
              +{SKIP_SECONDS}s
            </button>

            <span className="player__time">
              {clock(current)} / {clock(total)}
            </span>

            {showStartOver && (
              <button
                className="btn btn--ghost btn--sm"
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
                const next = Number(event.target.value);
                setVolume(next);
                setMuted(next === 0);
              }}
            />

            <button className="btn btn--ghost btn--icon" aria-label="Picture in picture" onClick={() => void togglePip()}>
              <IconPip width={20} height={20} />
            </button>

            <button className="btn btn--ghost btn--icon" aria-label="Fullscreen" onClick={() => void toggleFullscreen()}>
              <IconFullscreen width={20} height={20} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function readStoredVolume(): number {
  try {
    const value = Number(localStorage.getItem(VOLUME_KEY));
    return Number.isFinite(value) && value >= 0 && value <= 1 ? value : 1;
  } catch {
    return 1;
  }
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
  const match = /s(\d{1,2})[\s._-]?e(\d{1,3})/i.exec(file.fileName);
  if (match) return `S${match[1]?.padStart(2, "0")}E${match[2]?.padStart(2, "0")}`;
  return formatDuration(file.duration);
}
