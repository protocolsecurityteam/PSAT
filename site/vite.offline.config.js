import { mergeConfig } from "vite";
import base from "./vite.config.js";
export default mergeConfig(base, {
  envDir: false,
  plugins: [{
    name: "offline-fonts",
    transformIndexHtml(html) {
      return html.replace(/<link\b[^>]*https:\/\/fonts\.(?:googleapis|gstatic)\.com[^>]*>/gs, "");
    },
  }],
  server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy: { "/api": "http://127.0.0.1:1" } },
});
