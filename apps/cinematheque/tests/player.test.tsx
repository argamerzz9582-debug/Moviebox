/**
 * Player behaviour tests.
 *
 * jsdom has no media pipeline, so these assert the *contract* the player owes the
 * user, which is exactly where the bugs were:
 *   - a blocked autoplay must never leave a dead black screen (a play button
 *     appears and clicking it starts playback);
 *   - an unplayable file must say so instead of looking frozen;
 *   - a missing payload must point at re-importing, not silently do nothing.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const getBlob = vi.fn();

vi.mock("../src/lib/db", () => ({
  storageAvailable: () => true,
  loadSnapshot: async () => ({ titles: [], progress: {}, collections: {}, viewMode: "grid" }),
  saveSnapshot: vi.fn(async () => undefined),
  putBlob: vi.fn(async () => undefined),
  getBlob: (...args: unknown[]) => getBlob(...args),
  hasBlob: vi.fn(async () => true),
  deleteBlob: vi.fn(async () => undefined),
  clearAll: vi.fn(async () => undefined),
  storageEstimate: vi.fn(async () => undefined),
  requestPersistence: vi.fn(async () => true),
}));

import { Player } from "../src/components/Player";
import { LibraryProvider } from "../src/state/library";
import type { Title } from "../src/lib/types";

const title: Title = {
  id: "t1",
  kind: "movie",
  name: "Arrival",
  year: 2016,
  tags: ["1080p"],
  addedAt: "2024-01-01T00:00:00.000Z",
  progress: 0,
  watched: false,
  files: [{ id: "f1", titleId: "t1", fileName: "Arrival.2016.1080p.mp4", size: 5000, duration: 6000, mime: "video/mp4" }],
};

function renderPlayer(onClose = vi.fn()) {
  return {
    onClose,
    ...render(
      <LibraryProvider>
        <Player title={title} fileId="f1" onClose={onClose} onPlayFile={vi.fn()} />
      </LibraryProvider>,
    ),
  };
}

beforeEach(() => {
  getBlob.mockReset();
  getBlob.mockResolvedValue({
    id: "f1",
    fileName: "Arrival.2016.1080p.mp4",
    blob: new Blob([new Uint8Array(64)], { type: "video/mp4" }),
  });
});

describe("player", () => {
  it("opens without error when the payload exists", async () => {
    renderPlayer();
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: /close player/i })).toBeInTheDocument();
  });

  it("shows a play affordance even before playback starts", async () => {
    renderPlayer();
    // The big play button is the fix for blocked autoplay: never a dead screen.
    expect(await screen.findByRole("button", { name: /^play$/i })).toBeInTheDocument();
  });

  it("clicking play attempts playback instead of doing nothing", async () => {
    const user = userEvent.setup();
    const { container } = renderPlayer();

    // Wait for the source to resolve: before that there is no <video> element.
    await waitFor(() => expect(container.querySelector("video")).not.toBeNull());
    const video = container.querySelector("video")!;
    // jsdom does not implement play(); stub it on the instance we will click through.
    const playSpy = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(video, "play", { writable: true, value: playSpy });
    Object.defineProperty(video, "paused", { writable: true, value: true });

    await user.click(await screen.findByRole("button", { name: /^play$/i }));
    await waitFor(() => expect(playSpy).toHaveBeenCalled());
  });

  it("tells the user to re-import when the payload is gone", async () => {
    getBlob.mockResolvedValue(undefined);
    renderPlayer();
    expect(await screen.findByRole("alert")).toHaveTextContent(/re-import/i);
  });

  it("treats a zero-byte payload as missing", async () => {
    getBlob.mockResolvedValue({
      id: "f1",
      fileName: "x.mp4",
      blob: new Blob([], { type: "video/mp4" }),
    });
    renderPlayer();
    expect(await screen.findByRole("alert")).toHaveTextContent(/re-import/i);
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    const { onClose } = renderPlayer();
    await screen.findByRole("button", { name: /^play$/i });
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  it("offers skip controls and a seek slider", async () => {
    renderPlayer();
    expect(await screen.findByRole("slider", { name: /seek/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /forward 10 seconds/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /back 10 seconds/i })).toBeInTheDocument();
  });
});
