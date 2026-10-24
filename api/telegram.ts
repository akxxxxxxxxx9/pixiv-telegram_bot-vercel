import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  acquireVercelStateLock,
  bot,
  isVercelUpdateProcessed,
  markVercelUpdateProcessed,
  prepareVercelRequest,
  releaseVercelStateLock,
  saveVercelState
} from '../bot.js';

type VercelRequest = IncomingMessage & {
  body?: unknown;
};

type TelegramUpdate = Parameters<typeof bot.handleUpdate>[0];

function writeJson(res: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function isValidSecret(received: string | undefined, expected: string): boolean {
  if (!received) return false;
  const receivedBuffer = Buffer.from(received);
  const expectedBuffer = Buffer.from(expected);
  return receivedBuffer.length === expectedBuffer.length && timingSafeEqual(receivedBuffer, expectedBuffer);
}

async function readRequestBody(req: VercelRequest): Promise<unknown> {
  if (req.body !== undefined) {
    if (typeof req.body === 'string') return JSON.parse(req.body);
    if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString('utf8'));
    return req.body;
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 1024 * 1024) throw new Error('Request body exceeds the 1 MB limit');
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export default async function handler(req: VercelRequest, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    writeJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  const expectedSecret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!expectedSecret) {
    writeJson(res, 500, { error: 'TELEGRAM_WEBHOOK_SECRET is not configured' });
    return;
  }

  const headerSecret = req.headers['x-telegram-bot-api-secret-token'];
  const receivedSecret = typeof headerSecret === 'string' ? headerSecret : undefined;
  if (!isValidSecret(receivedSecret, expectedSecret)) {
    writeJson(res, 401, { error: 'Unauthorized' });
    return;
  }

  try {
    const update = await readRequestBody(req) as TelegramUpdate;
    if (!Number.isSafeInteger(update?.update_id)) {
      writeJson(res, 400, { error: 'Invalid Telegram update' });
      return;
    }

    const lock = await acquireVercelStateLock();
    if (!lock) {
      writeJson(res, 503, { error: 'Bot is busy; retry later' });
      return;
    }

    let alreadyProcessed = false;
    try {
      alreadyProcessed = await isVercelUpdateProcessed(update.update_id);
      if (!alreadyProcessed) {
        await prepareVercelRequest();
        await bot.handleUpdate(update);
        await saveVercelState();
        await markVercelUpdateProcessed(update.update_id);
      }
    } finally {
      await releaseVercelStateLock(lock);
    }
    writeJson(res, 200, { ok: true, duplicate: alreadyProcessed });
  } catch (error) {
    console.error('Telegram webhook request failed:', error);
    writeJson(res, 500, { error: 'Webhook processing failed' });
  }
}
