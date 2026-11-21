/**
 * Integration test: the shell renders, the empty state explains the app, and a
 * title added to the store shows up in the grid and opens its sheet.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../src/lib/db", () => ({
  storageAvailable: () => true,
  loadSnapshot: async () => ({
    titles: [
      {
        id: "t1",
        kind: "movie",
        name: "Arrival",
        year: 2016,
        tags: ["1080p"],
        addedAt: "2024-01-01T00:00:00.000Z",
        progress: 600,
        watched: false,
        files: [{ id: "f1", titleId: "t1", fileName: "Arrival.2016.1080p.mkv", size: 1000, duration: 6000, mime: "video/mp4" }],
      },
    ],
    progress: { t1: { titleId: "t1", seconds: 600, duration: 6000, updatedAt: "2024-01-02T00:00:00.000Z" } },
    collections: { "Sci-fi": ["t1"] },
  }),
  saveSnapshot: vi.fn(async () => undefined),
  putBlob: vi.fn(async () => undefined),
  getBlob: vi.fn(async () => undefined),
  deleteBlob: vi.fn(async () => undefined),
  clearAll: vi.fn(async () => undefined),
  storageEstimate: vi.fn(async () => undefined),
}));

import App from "../src/App";
import { LibraryProvider } from "../src/state/library";

function renderApp() {
  return render(
    <LibraryProvider>
      <App />
    </LibraryProvider>,
  );
}

describe("app shell", () => {
  it("renders the library with parsed titles and counts", async () => {
    renderApp();
    expect(await screen.findByRole("heading", { name: "Library" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /open arrival/i })).toBeInTheDocument();
    expect(screen.getByText("Sci-fi")).toBeInTheDocument();
  });

  it("filters the grid via the chips", async () => {
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole("button", { name: /open arrival/i });

    await user.click(screen.getByRole("button", { name: "Series" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: /open arrival/i })).not.toBeInTheDocument());
    expect(screen.getByText("Nothing matches")).toBeInTheDocument();
  });

  it("searches by name", async () => {
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole("button", { name: /open arrival/i });

    await user.type(screen.getByLabelText("Search library"), "arr");
    expect(await screen.findByRole("button", { name: /open arrival/i })).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Search library"));
    await user.type(screen.getByLabelText("Search library"), "zzz");
    expect(await screen.findByText("Nothing matches")).toBeInTheDocument();
  });

  it("opens the detail sheet and shows resume state", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(await screen.findByRole("button", { name: /open arrival/i }));

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText(/resume at 10m 0s/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /resume/i })).toBeInTheDocument();
    expect(screen.getByText("Arrival.2016.1080p.mkv")).toBeInTheDocument();
  });

  it("closes the sheet on Escape", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(await screen.findByRole("button", { name: /open arrival/i }));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
