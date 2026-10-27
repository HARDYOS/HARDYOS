/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const daemon = process.env.HARDYD_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: daemon, changeOrigin: true, ws: true },
      // Share link pages, served by hardyd outside the desktop.
      "/s/": { target: daemon, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    // noVNC (the VM console) uses top-level await.
    target: "es2022",
  },
  optimizeDeps: {
    esbuildOptions: { target: "es2022" },
  },
  test: {
    environment: "jsdom",
    globals: false,
  },
});
