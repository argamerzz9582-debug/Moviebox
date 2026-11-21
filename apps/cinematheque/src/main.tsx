import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { LibraryProvider } from "./state/library";
import "./styles/tokens.css";
import "./styles/app.css";

const container = document.getElementById("root");
if (!container) throw new Error("#root missing from index.html");

createRoot(container).render(
  <StrictMode>
    <LibraryProvider>
      <App />
    </LibraryProvider>
  </StrictMode>,
);
