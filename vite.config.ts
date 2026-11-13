import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, Plugin } from 'vite';
import express from 'express';
import scannerRouter from './src/server/scanner-routes.ts';
import v2Router from './src/v2/server/v2-routes.ts';

const apiPlugin = (): Plugin => ({
  name: 'wpsentinel-api',
  configureServer(server) {
    const app = express();
    app.use('/api/v2', v2Router);
    app.use(express.json());
    app.use('/api', scannerRouter);
    server.middlewares.use(app);
  }
});

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), apiPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(process.cwd(), '.'),
      },
    },
    server: {
      port: 3000,
      host: '0.0.0.0',
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
