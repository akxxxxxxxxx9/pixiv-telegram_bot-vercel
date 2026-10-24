import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  acquireVercelStateLock,
  pollPixivFavorites,
  prepareVercelRequest,
  releaseVercelStateLock,
  saveVercelState
} from '../bot.js';

function writeJson(res: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    writeJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  const secret = process.env.CRON_SECRET;
  if (!secret) {
    writeJson(res, 500, { error: 'CRON_SECRET is not configured' });
    return;
  }

  if (req.headers.authorization !== `Bearer ${secret}`) {
    writeJson(res, 401, { error: 'Unauthorized' });
    return;
  }

  try {
    const lock = await acquireVercelStateLock();
    if (!lock) {
      writeJson(res, 503, { error: 'Bot is busy; retry later' });
      return;
    }

    let result: Awaited<ReturnType<typeof pollPixivFavorites>>;
    try {
      await prepareVercelRequest();
      result = await pollPixivFavorites();
      await saveVercelState();
    } finally {
      await releaseVercelStateLock(lock);
    }
    writeJson(res, 200, result);
  } catch (error) {
    console.error('Pixiv favorite cron failed:', error);
    writeJson(res, 500, { error: 'Favorite check failed' });
  }
}
