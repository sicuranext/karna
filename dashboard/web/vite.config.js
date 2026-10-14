import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Buildless is out: everything is compiled and vendored at build time so the
// shipped bundle pulls nothing from a CDN at runtime. The dev server proxies
// /api to the FastAPI backend so the browser only ever talks to one
// origin — same contract nginx enforces in the production container.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.KARNA_API_TARGET || "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2020",
  },
});
