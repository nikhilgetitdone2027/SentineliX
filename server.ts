/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { apiRouter } from './backend/routes/api';

// Load environment variables
dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Mount the modular API Router on both /api (backward compatibility) and / (new endpoints root)
app.use('/api', apiRouter);
app.use('/', apiRouter);

// ============================================================================
// VITE OR STATIC MIDDLEWARE SETUP
// ============================================================================

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    
    // Serve index.html for non-API client routes
    app.get('*', (req, res, next) => {
      // Skip API requests if any leaked through
      if (req.path.startsWith('/api/') || req.path === '/health' || req.path === '/upload-pcap' || req.path === '/dashboard' || req.path === '/alerts') {
        return next();
      }
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelX Enterprise Server successfully running on http://0.0.0.0:${PORT}`);
  });

  // Start the Python FastAPI Packet Parser microservice on loopback port 8000
  console.log('SentinelX: Bootstrapping Python Packet Parser microservice...');
  try {
    const { spawn } = await import('child_process');
    const pythonProcess = spawn('python3', [
      '-m', 'uvicorn',
      'backend.packet_parser.main:app',
      '--port', '8090',
      '--host', '127.0.0.1'
    ], {
      stdio: 'inherit',
      detached: false
    });

    pythonProcess.on('error', (err) => {
      console.error('SentinelX: Failed to start Python Packet Parser microservice:', err);
    });

    process.on('exit', () => {
      try {
        pythonProcess.kill();
      } catch (e) {}
    });
  } catch (err) {
    console.error('SentinelX: Exception during Python microservice spawn:', err);
  }
}

startServer();
