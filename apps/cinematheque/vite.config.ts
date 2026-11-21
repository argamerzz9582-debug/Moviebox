import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // The preview proxy terminates TLS and forwards to 0.0.0.0:5173. Allowing any
  // host/origin keeps the sandbox preview (and phone-on-LAN testing) working;
  // there is no auth or cookie surface in this app that the setting could leak.
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    cors: true,
  },
  preview: { host: "0.0.0.0", port: 4173, strictPort: true, allowedHosts: true },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    css: false,
  },
});
