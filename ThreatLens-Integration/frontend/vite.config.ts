import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    // Forward API calls to the backend during development so the app can keep
    // VITE_API_BASE_URL as the relative "/api/v1" and never hit CORS.
    // Run the backend with:  cd backend && uvicorn app.main:app --port 8000
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
