import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeTargetUrl } from './server/urlAnalysisService';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;
  const isProd = process.env.NODE_ENV === 'production';

  app.use(express.json());

  // API Route: POST /api/analyze
  app.post('/api/analyze', async (req, res) => {
    const { url } = req.body || {};
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'Missing required "url" field in request body'
      });
    }

    try {
      const result = await analyzeTargetUrl(url);
      return res.status(result.success ? 200 : 422).json(result);
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: `Server analysis error: ${err.message || 'Internal error'}`
      });
    }
  });

  // API Route: GET /api/analyze (convenient for curl/testing in browser)
  app.get('/api/analyze', async (req, res) => {
    const url = req.query.url as string;
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'Missing required "url" query parameter, e.g. /api/analyze?url=https://example.com'
      });
    }

    try {
      const result = await analyzeTargetUrl(url);
      return res.status(result.success ? 200 : 422).json(result);
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: `Server analysis error: ${err.message || 'Internal error'}`
      });
    }
  });

  // Health check endpoint
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'VERISCAN Trust Analysis API', timestamp: new Date().toISOString() });
  });

  // Mount Vite middleware in development mode, or static file server in production
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[VERISCAN] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[VERISCAN] Failed to start server:', err);
  process.exit(1);
});
