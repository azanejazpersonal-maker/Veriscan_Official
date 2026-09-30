import type { IncomingMessage } from 'node:http';
import { analyzeTargetUrl } from '../server/urlAnalysisService.ts';

async function parseRequestBody(req: IncomingMessage): Promise<any> {
  if ((req as any).body) {
    return (req as any).body;
  }
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  let targetUrl = '';

  if (req.method === 'GET') {
    targetUrl = (req.query?.url || '') as string;
  } else if (req.method === 'POST') {
    const parsedBody = await parseRequestBody(req);
    targetUrl = parsedBody?.url || req.body?.url || '';
  } else {
    return res.status(405).json({
      success: false,
      error: 'Method Not Allowed. Use POST or GET.'
    });
  }

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Missing required "url" field in request'
    });
  }

  try {
    const result = await analyzeTargetUrl(targetUrl);
    return res.status(result.success ? 200 : 422).json(result);
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: `Server analysis error: ${err?.message || 'Internal error'}`
    });
  }
}
