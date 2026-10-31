import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [sveltekit()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    // Pin to IPv4 loopback. The template's `false` makes Vite bind whatever `localhost`
    // resolves to, which on Node 17+ is IPv6 `[::1]`. WebView2 then tries IPv4
    // `127.0.0.1` first, finds nothing, and waits out a ~10-20s connect timeout before
    // failing over to IPv6 - the black-window delay on Windows. Forcing 127.0.0.1 on
    // both this and tauri.conf.json's devUrl keeps everything on one IPv4 address.
    host: host || "127.0.0.1",
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
