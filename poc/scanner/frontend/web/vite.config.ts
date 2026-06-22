import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the SPA calls same-origin "/api/*"; proxy that to the frontend server
// (uvicorn on :8000), which in turn forwards to the db-api. Point the target at
// the db-api directly (with a rewrite stripping "/api") if you prefer to skip
// running the python server during pure-UI work.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
