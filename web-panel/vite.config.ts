import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Relative asset URLs: the server can mount the panel under any path (CC_PANEL_PATH)
  base: './',
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, '.') },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8443',
        changeOrigin: true,
      },
      '/client-api': {
        target: 'http://127.0.0.1:8443',
        changeOrigin: true,
      },
    },
  },
});
