import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Cerberus Dashboard — Vite config
// host: true binds to 0.0.0.0, not just localhost, so you can open the
// dashboard from your phone's browser at http://<your-pc-ip>:5173 while
// on the same Wi-Fi — same reasoning as api_host=0.0.0.0 on the backend.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
  },
});
