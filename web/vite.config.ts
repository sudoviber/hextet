import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // 本地 `npm run dev` 把 /api 与 /healthz 转发到本机 daemon 的 HTTP 状态服务
      // （默认 http_port = 8080）。
      "/api": "http://127.0.0.1:8080",
      "/healthz": "http://127.0.0.1:8080",
    },
  },
  build: {
    // 构建产物默认输出到 dist/（axum 的 [node] web_dir 指向这里即可）
    outDir: "dist",
  },
});
