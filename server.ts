import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import scannerRouter from './src/server/scanner-routes.ts';
import v2Router from './src/v2/server/v2-routes.ts';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use('/api/v2', v2Router);
app.use(express.json());
app.use('/api', scannerRouter);

// Serve static frontend in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`WP Sentinel server running on http://0.0.0.0:${PORT}`);
});
