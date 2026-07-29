import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend dev server is PLAIN HTTP on localhost:5174. It is NOT a
// user-facing transport — the only thing a client ever talks to is the Grade D
// SSLv3 reverse proxy (reverse-proxy-dev) on https://localhost:8443, which
// forwards to this server over the Docker host gateway. There is no TLS 1.2/1.3
// dev cert here anymore; SSLv3 is the sole transport. (The dev-https cert under
// docker/certs/dev-https is still mounted into the reverse-proxy-dev container
// as the SSLv3 cert — it is just no longer used by vite.)

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5174,
    // Proxy the API and WebSocket endpoints to the FastAPI backend so the
    // frontend can use same-origin `/api/v1` URLs in dev without CORS churn.
    // In Docker, the reverse proxy handles this routing instead.
    proxy: {
      // The WebSocket endpoint is /api/v1/ws, so the /api proxy MUST enable
      // ws upgrading — otherwise the ws://localhost:5174/api/v1/ws upgrade is
      // never forwarded to the backend and closes immediately.
      "/api": {
        target: "http://localhost:8001",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});