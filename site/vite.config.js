import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const host = process.env.VITE_DEV_HOST || "127.0.0.1";
const port = Number(process.env.VITE_DEV_PORT || 5173);
const apiProxyTarget = process.env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host,
    port,
    proxy: {
      "/api": apiProxyTarget,
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Pre-split heavy graph deps so the home page (`/`) doesn't download
    // ReactFlow + ELK until the user opens a company graph, and each vendor
    // chunk caches independently across deploys (React almost never changes;
    // the app chunk does on every deploy).
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          reactflow: ["@xyflow/react"],
          elk: ["elkjs/lib/elk.bundled.js"],
        },
      },
    },
  },
});
