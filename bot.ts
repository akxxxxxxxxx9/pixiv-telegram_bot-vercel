import { Bot, InputFile, InlineKeyboard } from 'grammy';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { exec } from 'child_process';
import { randomUUID, timingSafeEqual } from 'crypto';
import util from 'util';
import AdmZip from 'adm-zip';
import dotenv from 'dotenv';

dotenv.config();

const execAsync = util.promisify(exec);
const IS_VERCEL = process.env.VERCEL === '1';
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const BOT_PASSWORD = process.env.BOT_PASSWORD || '';
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').replace(/^@/, '').trim().toLowerCase();

if (!BOT_TOKEN) {
  throw new Error('请配置 TELEGRAM_BOT_TOKEN');
}

if (!BOT_PASSWORD) {
  throw new Error('请配置 BOT_PASSWORD');
}

const bot = new Bot(BOT_TOKEN);
let sendAllImagesMode = false;
const authorizedUserIds = new Set<number>();
const rootGrantedUserIds = new Set<number>();
const blockedUserIds = new Set<number>();
const userStatusMap = new Map<number, {
  username: string;
  passwordVerified: boolean;
  rootGranted: boolean;
  blocked: boolean;
  isAdmin: boolean;
}>();
let ACCESS_CONTROL_FILE = path.join(path.resolve(process.env.DATA_DIR || './data'), 'access-control.json');

type PersistedAccessUser = {
  id: number;
  username: string;
  authorized: boolean;
  blocked: boolean;
};

function loadAccessStateFromDisk(): { users: PersistedAccessUser[]; canRewrite: boolean } {
  try {
    if (!fs.existsSync(ACCESS_CONTROL_FILE)) {
      return { users: [], canRewrite: true };
    }

    const raw = fs.readFileSync(ACCESS_CONTROL_FILE, 'utf8');
    const parsed = JSON.parse(raw) as {
      users?: Array<{ id?: unknown; username?: unknown; authorized?: unknown; blocked?: unknown }>;
      rootGranted?: unknown[];
      blocked?: unknown[];
    };
    const users = new Map<number, PersistedAccessUser>();

    if (Array.isArray(parsed?.users)) {
      for (const entry of parsed.users) {
        const id = Number(entry?.id);
        if (!Number.isSafeInteger(id) || id <= 0) continue;
        users.set(id, {
          id,
          username: normalizeUsername(typeof entry.username === 'string' ? entry.username : '') || `user_${id}`,
          authorized: entry.authorized === true,
          blocked: entry.blocked === true
        });
      }
    }

    const legacyRootGranted = Array.isArray(parsed?.rootGranted)
      ? parsed.rootGranted.map(Number).filter((id) => Number.isSafeInteger(id) && id > 0)
      : [];
    const legacyBlocked = Array.isArray(parsed?.blocked)
      ? parsed.blocked.map(Number).filter((id) => Number.isSafeInteger(id) && id > 0)
      : [];

    for (const id of new Set([...legacyRootGranted, ...legacyBlocked])) {
      const user = users.get(id) || { id, username: `user_${id}`, authorized: false, blocked: false };
      user.authorized ||= legacyRootGranted.includes(id);
      user.blocked ||= legacyBlocked.includes(id);
      users.set(id, user);
    }

    return { users: [...users.values()], canRewrite: true };
  } catch (error: any) {
    console.warn('读取权限持久化文件失败:', error.message);
    return { users: [], canRewrite: false };
  }
}

function saveAccessStateToDisk(): void {
  if (IS_VERCEL) return;

  const userIds = new Set([...userStatusMap.keys(), ...rootGrantedUserIds, ...blockedUserIds]);
  const users: PersistedAccessUser[] = [...userIds].sort((a, b) => a - b).map((id) => {
    const status = userStatusMap.get(id);
    const username = status?.username || `user_${id}`;
    return {
      id,
      username,
      authorized: rootGrantedUserIds.has(id),
      blocked: blockedUserIds.has(id)
    };
  });
  const temporaryFile = `${ACCESS_CONTROL_FILE}.${process.pid}.tmp`;

  try {
    fs.mkdirSync(path.dirname(ACCESS_CONTROL_FILE), { recursive: true });
    fs.writeFileSync(temporaryFile, JSON.stringify({ users }, null, 2), 'utf8');
    fs.renameSync(temporaryFile, ACCESS_CONTROL_FILE);
  } catch (error: any) {
    try {
      if (fs.existsSync(temporaryFile)) fs.unlinkSync(temporaryFile);
    } catch {}
    console.warn('保存权限持久化文件失败:', error.message);
  }
}

function loadAccessStateToMemory(): void {
  if (IS_VERCEL) return;

  const state = loadAccessStateFromDisk();
  for (const user of state.users) {
    if (user.authorized) rootGrantedUserIds.add(user.id);
    if (user.blocked) blockedUserIds.add(user.id);
    userStatusMap.set(user.id, {
      username: user.username,
      passwordVerified: false,
      rootGranted: user.authorized,
      blocked: user.blocked,
      isAdmin: isAdminUsername(user.username)
    });
  }
  if (state.canRewrite) saveAccessStateToDisk();
}

function normalizeUsername(value?: string | null): string {
  return String(value ?? '').replace(/^@/, '').trim().toLowerCase();
}

function isAdminUsername(username?: string | null): boolean {
  return !!ADMIN_USERNAME && normalizeUsername(username) === ADMIN_USERNAME;
}

function syncUserStatus(user: { id: number; username?: string | null } | null | undefined) {
  if (!user) return;

  const previousStatus = userStatusMap.get(user.id);
  const username = normalizeUsername(user.username) || previousStatus?.username || `user_${user.id}`;
  const status = previousStatus || {
    username,
    passwordVerified: false,
    rootGranted: false,
    blocked: false,
    isAdmin: false
  };

  status.username = username;
  status.passwordVerified = authorizedUserIds.has(user.id);
  status.rootGranted = rootGrantedUserIds.has(user.id);
  status.blocked = blockedUserIds.has(user.id);
  status.isAdmin = isAdminUsername(username);
  userStatusMap.set(user.id, status);

  if (!previousStatus || previousStatus.username !== status.username ||
      previousStatus.rootGranted !== status.rootGranted || previousStatus.blocked !== status.blocked ||
      previousStatus.isAdmin !== status.isAdmin) {
    saveAccessStateToDisk();
  }
}

function findUserByUsername(rawUsername: string): { id: number; username: string } | null {
  const username = normalizeUsername(rawUsername);
  if (!username) return null;

  for (const [userId, status] of userStatusMap.entries()) {
    if (normalizeUsername(status.username) === username) {
      return { id: userId, username: status.username };
    }
  }

  return null;
}

async function resolveTargetUserByUsername(ctx: any, rawUsername: string): Promise<{ id: number; username: string } | null> {
  const username = normalizeUsername(rawUsername);
  if (!username) return null;

  const known = findUserByUsername(username);
  if (known) return known;

  const mention = (ctx.message?.text || '').match(/@([A-Za-z0-9_]{1,32})/g)?.[0]?.replace(/^@/, '');
  if (mention && normalizeUsername(mention) === username) {
    for (const [userId, status] of userStatusMap.entries()) {
      if (normalizeUsername(status.username) === username) {
        return { id: userId, username: status.username };
      }
    }
  }

  return null;
}

function userHasRootAccess(userId?: number): boolean {
  return !!userId && (rootGrantedUserIds.has(userId) || isAdminUsername(userStatusMap.get(userId)?.username));
}

function userIsBlocked(userId?: number): boolean {
  return !!userId && blockedUserIds.has(userId);
}

function userCanUseUgoira(user?: { id?: number; username?: string | null } | null): boolean {
  if (!user?.id) return false;
  if (blockedUserIds.has(user.id)) return false;
  if (isAdminUsername(user.username)) return true;
  return rootGrantedUserIds.has(user.id);
}

bot.use(async (ctx, next) => {
  const messageText = ctx.message && 'text' in ctx.message ? ctx.message.text : undefined;
  const chatId = ctx.chat?.id;
  const messageId = ctx.message?.message_id;
  const passwordCommand = messageText?.match(/^\/password(?:@\w+)?(?:\s+([\s\S]*))?$/);

  if (ctx.from) {
    if (!authorizedUserIds.has(ctx.from.id) && await isVercelPasswordVerified(ctx.from.id)) {
      authorizedUserIds.add(ctx.from.id);
    }
    syncUserStatus(ctx.from);
    if (userIsBlocked(ctx.from.id)) {
      if (ctx.callbackQuery) {
        await ctx.answerCallbackQuery({ text: '你的账号已被封禁，无法使用机器人。', show_alert: true }).catch(() => {});
      } else if (messageText) {
        await ctx.reply('🚫 你的账号已被封禁，无法使用机器人。');
      }
      return;
    }

    if (isAdminUsername(ctx.from.username)) {
      authorizedUserIds.add(ctx.from.id);
      rootGrantedUserIds.add(ctx.from.id);
      syncUserStatus(ctx.from);
      await next();
      return;
    }

    if (rootGrantedUserIds.has(ctx.from.id)) {
      authorizedUserIds.add(ctx.from.id);
      syncUserStatus(ctx.from);
      await next();
      return;
    }
  }

  if (passwordCommand) {
    if (ctx.chat?.type !== 'private') {
      if (chatId !== undefined && messageId !== undefined) {
        await ctx.api.deleteMessage(chatId, messageId).catch(() => {});
      }
      await ctx.reply('🔐 请在与机器人的私聊中发送密码，不能在群组中验证。');
      return;
    }

    const submittedPassword = (passwordCommand[1] || '').trim();
    const submittedBuffer = Buffer.from(submittedPassword);
    const expectedBuffer = Buffer.from(BOT_PASSWORD);
    const isValid = submittedBuffer.length === expectedBuffer.length && timingSafeEqual(submittedBuffer, expectedBuffer);

    if (chatId !== undefined && messageId !== undefined) {
      await ctx.api.deleteMessage(chatId, messageId).catch(() => {});
    }
    if (isValid && ctx.from) {
      authorizedUserIds.add(ctx.from.id);
      await saveVercelPasswordSession(ctx.from.id);
      syncUserStatus(ctx.from);
      await ctx.reply('✅ 密码正确，已授权使用机器人。');
    } else {
      await ctx.reply('❌ 密码错误。请发送 <code>/password 密码值</code> 重试。', { parse_mode: 'HTML' });
    }
    return;
  }

  if (messageText && /^\/(?:start|help)(?:@\w+)?(?:\s|$)/i.test(messageText)) {
    await next();
    return;
  }

  if (ctx.from && authorizedUserIds.has(ctx.from.id)) {
    await next();
    return;
  }

  if (ctx.callbackQuery) {
    await ctx.answerCallbackQuery({ text: '请先私聊机器人发送 /password 密码值', show_alert: true }).catch(() => {});
  } else if (messageText && (/^\//.test(messageText) || extractPixivId(messageText))) {
    await ctx.reply('🔒 请先私聊机器人发送 <code>/password 密码值</code> 完成验证。', { parse_mode: 'HTML' });
  }
});

const parseTaskQueue: Array<{
  id: number;
  chatId: number;
  userId: number;
  run: (signal: AbortSignal) => Promise<void>;
  resolve: () => void;
}> = [];

let activeParseTask: {
  id: number;
  chatId: number;
  userId: number;
  abortController: AbortController;
} | null = null;

let nextParseTaskId = 1;

function enqueueParseTask(chatId: number, userId: number, run: (signal: AbortSignal) => Promise<void>): Promise<void> {
  return new Promise((resolve) => {
    parseTaskQueue.push({ id: nextParseTaskId++, chatId, userId, run, resolve });
    if (!activeParseTask) {
      void drainParseQueue();
    }
  });
}

async function drainParseQueue(): Promise<void> {
  while (parseTaskQueue.length > 0) {
    const task = parseTaskQueue.shift();
    if (!task) continue;

    const abortController = new AbortController();
    activeParseTask = {
      id: task.id,
      chatId: task.chatId,
      userId: task.userId,
      abortController
    };

    try {
      await task.run(abortController.signal);
    } catch (error) {
      console.error(`解析任务 #${task.id} 未处理异常:`, error);
    } finally {
      task.resolve();
      if (activeParseTask?.id === task.id) {
        activeParseTask = null;
      }
    }
  }
}

function stopCurrentParseTask(chatId: number, userId: number): boolean {
  if (!activeParseTask) return false;
  const isSameChat = activeParseTask.chatId === chatId;
  const isSameUser = activeParseTask.userId === userId;
  if (!isSameChat && !isSameUser) return false;

  activeParseTask.abortController.abort();
  return true;
}

const SUBSCRIPTION_FILE = path.join(path.resolve(process.env.DATA_DIR || './data'), 'subscriptions.json');
const GROUP_CHAT_ID = Number(process.env.GROUP_CHAT_ID);
let subscriptionState: Record<string, SubscriptionEntry[]> = {};

function getConfiguredTargetChatIds(originalChatId: number): number[] {
  if (!Number.isSafeInteger(GROUP_CHAT_ID) || GROUP_CHAT_ID === 0 || GROUP_CHAT_ID === originalChatId) return [];
  return [GROUP_CHAT_ID];
}

async function relayToConfiguredChats(
  ctx: any,
  originalChatId: number,
  sendAction: (targetChatId: number) => Promise<any>
): Promise<void> {
  const targetIds = getConfiguredTargetChatIds(originalChatId);
  for (const targetChatId of targetIds) {
    try {
      await sendAction(targetChatId);
    } catch (e: any) {
      console.warn(`转发到目标聊天 ${targetChatId} 失败:`, e.message);
    }
  }
}

async function relayTextToConfiguredChats(
  ctx: any,
  originalChatId: number,
  text: string,
  options?: any
): Promise<void> {
  await relayToConfiguredChats(ctx, originalChatId, async (targetChatId) => {
    await ctx.api.sendMessage(targetChatId, text, options);
  });
}

type BufferedAlbumPhoto = {
  buffer: Buffer;
  filename: string;
  caption?: string;
  parse_mode?: 'HTML';
};

const MAX_ALBUM_PHOTOS = 10;
const MAX_ALBUM_REQUEST_BYTES = 35 * 1024 * 1024;
const MAX_TELEGRAM_PHOTO_BYTES = 10 * 1024 * 1024;

function isTelegramEntityTooLarge(error: any): boolean {
  return error?.error_code === 413 || error?.error?.error_code === 413 ||
    /413|request entity too large/i.test(String(error?.description || error?.message || ''));
}

async function sendBufferedPhotoAlbum(
  photos: BufferedAlbumPhoto[],
  sendAlbum: (media: any[]) => Promise<unknown>,
  sendPhoto: (photo: InputFile, options?: any) => Promise<unknown>,
  sendDocument: (document: InputFile, options?: any) => Promise<unknown>
): Promise<void> {
  const sendSingle = async (photo: BufferedAlbumPhoto): Promise<void> => {
    const options = { caption: photo.caption, parse_mode: photo.parse_mode };
    const file = new InputFile(photo.buffer, photo.filename);

    try {
      if (photo.buffer.length > MAX_TELEGRAM_PHOTO_BYTES) {
        await sendDocument(file, options);
      } else {
        await sendPhoto(file, options);
      }
    } catch (error) {
      if (!isTelegramEntityTooLarge(error) || photo.buffer.length > MAX_TELEGRAM_PHOTO_BYTES) throw error;
      await sendDocument(new InputFile(photo.buffer, photo.filename), options);
    }
  };

  const sendChunk = async (chunk: BufferedAlbumPhoto[]): Promise<void> => {
    if (chunk.length === 1) {
      await sendSingle(chunk[0]);
      return;
    }

    const media = chunk.map((photo) => ({
      type: 'photo' as const,
      media: new InputFile(photo.buffer, photo.filename),
      caption: photo.caption,
      parse_mode: photo.parse_mode
    }));

    try {
      await sendAlbum(media);
    } catch (error) {
      if (!isTelegramEntityTooLarge(error)) throw error;
      const middle = Math.ceil(chunk.length / 2);
      await sendChunk(chunk.slice(0, middle));
      await sendChunk(chunk.slice(middle));
    }
  };

  let chunk: BufferedAlbumPhoto[] = [];
  let chunkBytes = 0;
  const flush = async (): Promise<void> => {
    if (!chunk.length) return;
    await sendChunk(chunk);
    chunk = [];
    chunkBytes = 0;
  };

  for (const photo of photos) {
    if (photo.buffer.length > MAX_TELEGRAM_PHOTO_BYTES) {
      await flush();
      await sendSingle(photo);
      continue;
    }

    if (chunk.length >= MAX_ALBUM_PHOTOS || chunkBytes + photo.buffer.length > MAX_ALBUM_REQUEST_BYTES) {
      await flush();
    }

    chunk.push(photo);
    chunkBytes += photo.buffer.length;
  }

  await flush();
}

type SubscriptionEntry = {
  artistId: string;
  artistName?: string;
  addedAt: number;
};

function loadSubscriptions(): Record<string, SubscriptionEntry[]> {
  if (IS_VERCEL) return subscriptionState;

  try {
    if (!fs.existsSync(SUBSCRIPTION_FILE)) return {};
    const raw = fs.readFileSync(SUBSCRIPTION_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (e: any) {
    console.warn('读取订阅缓存失败:', e.message);
    return {};
  }
}

function saveSubscriptions(data: Record<string, SubscriptionEntry[]>) {
  if (IS_VERCEL) {
    subscriptionState = data;
    return;
  }

  try {
    fs.writeFileSync(SUBSCRIPTION_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e: any) {
    console.warn('保存订阅缓存失败:', e.message);
  }
}

function listSubscriptions(chatId: number): SubscriptionEntry[] {
  const data = loadSubscriptions();
  return data[String(chatId)] || [];
}

function setSubscription(chatId: number, artistId: string, artistName?: string): boolean {
  const data = loadSubscriptions();
  const key = String(chatId);
  const entries = data[key] || [];
  const exists = entries.some((item) => item.artistId === artistId);
  if (exists) return false;
  entries.push({ artistId, artistName, addedAt: Date.now() });
  data[key] = entries;
  saveSubscriptions(data);
  return true;
}

function removeSubscription(chatId: number, artistId: string): boolean {
  const data = loadSubscriptions();
  const key = String(chatId);
  const entries = data[key] || [];
  const next = entries.filter((item) => item.artistId !== artistId);
  if (next.length === entries.length) return false;
  if (next.length === 0) {
    delete data[key];
  } else {
    data[key] = next;
  }
  saveSubscriptions(data);
  return true;
}

async function notifySubscribedArtists(chatId: number, illust: any): Promise<void> {
  if (!illust?.userId) return;
  const subs = listSubscriptions(chatId);
  if (!subs.length) return;

  const targetArtistId = String(illust.userId || illust.author?.id || '');
  const targetArtistName = illust.userName || illust.author?.name || '画师';
  const matched = subs.find((item) => item.artistId === targetArtistId);
  if (!matched) return;

  const channel = `https://www.pixiv.net/users/${targetArtistId}`;
  await bot.api.sendMessage(chatId, `🔔 你订阅的画师 <b>${escapeHtml(targetArtistName)}</b> 发布了新作品：\n🆔 <code>${targetArtistId}</code>\n🔗 <a href="${channel}">查看主页</a>`, {
    parse_mode: 'HTML'
  }).catch(() => {});
}

// 持久化存储目录与动态 Cookie 管理
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
if (!IS_VERCEL && !fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
ACCESS_CONTROL_FILE = path.join(DATA_DIR, 'access-control.json');
loadAccessStateToMemory();
const COOKIE_FILE = path.join(DATA_DIR, 'cookie.txt');
const PIXIV_FAVORITE_WATCH_FILE = path.join(DATA_DIR, 'pixiv-favorite-watch.json');
const PIXIV_FAVORITE_POLL_INTERVAL_MS = 5 * 60 * 1000;
const MAX_TRACKED_FAVORITE_IDS = 1000;
const PIXIV_FAVORITE_POLL_DESCRIPTION = IS_VERCEL
  ? '按 vercel.json 配置（默认每天一次）'
  : '每 5 分钟';

type PixivFavoriteWatch = {
  pixivUserId: string;
  chatId: number;
  ownerUserId: number;
  knownIllustIds: string[];
};

function loadPixivFavoriteWatch(): PixivFavoriteWatch | null {
  try {
    if (!fs.existsSync(PIXIV_FAVORITE_WATCH_FILE)) return null;
    const parsed = JSON.parse(fs.readFileSync(PIXIV_FAVORITE_WATCH_FILE, 'utf8'));
    if (!/^\d{1,12}$/.test(String(parsed?.pixivUserId)) ||
        !Number.isSafeInteger(parsed?.chatId) ||
        !Number.isSafeInteger(parsed?.ownerUserId) ||
        !Array.isArray(parsed?.knownIllustIds)) {
      throw new Error('收藏监控配置格式无效');
    }
    return {
      pixivUserId: String(parsed.pixivUserId),
      chatId: parsed.chatId,
      ownerUserId: parsed.ownerUserId,
      knownIllustIds: parsed.knownIllustIds.map(String).filter((id: string) => /^\d{1,12}$/.test(id)).slice(-MAX_TRACKED_FAVORITE_IDS)
    };
  } catch (error: any) {
    console.error('读取 Pixiv 收藏监控配置失败:', error.message);
    return null;
  }
}

let pixivFavoriteWatch = loadPixivFavoriteWatch();
let pixivFavoriteWatchVersion = 0;

function savePixivFavoriteWatch(): void {
  if (IS_VERCEL) return;

  const temporaryFile = `${PIXIV_FAVORITE_WATCH_FILE}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporaryFile, JSON.stringify(pixivFavoriteWatch, null, 2), 'utf8');
    fs.renameSync(temporaryFile, PIXIV_FAVORITE_WATCH_FILE);
  } catch (error) {
    try {
      if (fs.existsSync(temporaryFile)) fs.unlinkSync(temporaryFile);
    } catch {}
    throw error;
  }
}

// 启动时优先读取已保存的 cookie.txt，其次读取环境变量
let currentPixivCookie = '';
if (!IS_VERCEL && fs.existsSync(COOKIE_FILE)) {
  try {
    currentPixivCookie = fs.readFileSync(COOKIE_FILE, 'utf8').trim();
    console.log('📦 已从本地持久化文件加载 Pixiv Cookie');
  } catch (e: any) {
    console.warn('读取本地 Cookie 文件失败:', e.message);
  }
}
if (!currentPixivCookie && process.env.PIXIV_COOKIE) {
  currentPixivCookie = process.env.PIXIV_COOKIE.trim();
}

const UPSTASH_REDIS_REST_URL = process.env.UPSTASH_REDIS_REST_URL?.replace(/\/+$/, '');
const UPSTASH_REDIS_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REDIS_KEYS = {
  access: 'pixiv-bot:access',
  subscriptions: 'pixiv-bot:subscriptions',
  cookie: 'pixiv-bot:cookie',
  favoriteWatch: 'pixiv-bot:favorite-watch',
  sendAllImagesMode: 'pixiv-bot:send-all-images-mode',
  stateLock: 'pixiv-bot:state-lock'
} as const;

async function redisCommand<T>(command: (string | number)[]): Promise<T> {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) {
    throw new Error('请在 Vercel 配置 UPSTASH_REDIS_REST_URL 和 UPSTASH_REDIS_REST_TOKEN');
  }

  const response = await axios.post<{ result: T }>(UPSTASH_REDIS_REST_URL, command, {
    headers: {
      Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
      'Content-Type': 'application/json'
    },
    timeout: 10000
  });
  return response.data.result;
}

async function readRedisJson<T>(key: string, fallback: T): Promise<T> {
  const value = await redisCommand<string | null>(['GET', key]);
  if (!value) return fallback;
  return JSON.parse(value) as T;
}

export async function acquireVercelStateLock(): Promise<string | null> {
  const token = randomUUID();
  for (let attempt = 0; attempt < 20; attempt++) {
    const result = await redisCommand<string | null>(['SET', REDIS_KEYS.stateLock, token, 'NX', 'EX', 120]);
    if (result === 'OK') return token;
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  return null;
}

export async function releaseVercelStateLock(token: string): Promise<void> {
  await redisCommand([
    'EVAL',
    "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
    1,
    REDIS_KEYS.stateLock,
    token
  ]);
}

export async function isVercelUpdateProcessed(updateId: number): Promise<boolean> {
  return (await redisCommand<string | null>(['GET', `pixiv-bot:update:${updateId}`])) === '1';
}

export async function markVercelUpdateProcessed(updateId: number): Promise<void> {
  await redisCommand(['SET', `pixiv-bot:update:${updateId}`, '1', 'EX', 604800]);
}

export async function prepareVercelRequest(): Promise<void> {
  if (!IS_VERCEL) return;

  const [access, subscriptions, cookie, favoriteWatch, sendAllImages] = await Promise.all([
    readRedisJson<{ users?: PersistedAccessUser[] }>(REDIS_KEYS.access, { users: [] }),
    readRedisJson<Record<string, SubscriptionEntry[]>>(REDIS_KEYS.subscriptions, {}),
    redisCommand<string | null>(['GET', REDIS_KEYS.cookie]),
    readRedisJson<PixivFavoriteWatch | null>(REDIS_KEYS.favoriteWatch, null),
    readRedisJson<boolean>(REDIS_KEYS.sendAllImagesMode, false)
  ]);

  rootGrantedUserIds.clear();
  blockedUserIds.clear();
  userStatusMap.clear();

  for (const user of access.users || []) {
    if (!Number.isSafeInteger(user.id) || user.id <= 0) continue;
    if (user.authorized) rootGrantedUserIds.add(user.id);
    if (user.blocked) blockedUserIds.add(user.id);
    userStatusMap.set(user.id, {
      username: normalizeUsername(user.username) || `user_${user.id}`,
      passwordVerified: false,
      rootGranted: user.authorized === true,
      blocked: user.blocked === true,
      isAdmin: isAdminUsername(user.username)
    });
  }

  subscriptionState = subscriptions && typeof subscriptions === 'object' ? subscriptions : {};
  currentPixivCookie = cookie === null ? process.env.PIXIV_COOKIE?.trim() || '' : cookie;
  pixivFavoriteWatch = favoriteWatch;
  sendAllImagesMode = sendAllImages;
}

async function isVercelPasswordVerified(userId: number): Promise<boolean> {
  if (!IS_VERCEL || authorizedUserIds.has(userId)) return authorizedUserIds.has(userId);
  return (await redisCommand<string | null>(['GET', `pixiv-bot:verified:${userId}`])) === '1';
}

async function saveVercelPasswordSession(userId: number): Promise<void> {
  if (!IS_VERCEL) return;
  await redisCommand(['SET', `pixiv-bot:verified:${userId}`, '1', 'EX', 86400]);
}

export async function saveVercelState(): Promise<void> {
  if (!IS_VERCEL) return;

  const userIds = new Set([...userStatusMap.keys(), ...rootGrantedUserIds, ...blockedUserIds]);
  const users: PersistedAccessUser[] = [...userIds].sort((a, b) => a - b).map((id) => ({
    id,
    username: userStatusMap.get(id)?.username || `user_${id}`,
    authorized: rootGrantedUserIds.has(id),
    blocked: blockedUserIds.has(id)
  }));

  await Promise.all([
    redisCommand(['SET', REDIS_KEYS.access, JSON.stringify({ users })]),
    redisCommand(['SET', REDIS_KEYS.subscriptions, JSON.stringify(subscriptionState)]),
    redisCommand(['SET', REDIS_KEYS.cookie, currentPixivCookie]),
    redisCommand(['SET', REDIS_KEYS.favoriteWatch, JSON.stringify(pixivFavoriteWatch)]),
    redisCommand(['SET', REDIS_KEYS.sendAllImagesMode, JSON.stringify(sendAllImagesMode)])
  ]);
}

function getPixivHeaders(referer?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Referer': referer || 'https://www.pixiv.net/',
  };
  if (currentPixivCookie) {
    headers['Cookie'] = currentPixivCookie.startsWith('PHPSESSID=')
      ? currentPixivCookie
      : `PHPSESSID=${currentPixivCookie}`;
  }
  return headers;
}

function runShellCommand(command: string, signal?: AbortSignal): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = exec(command, { maxBuffer: 1024 * 1024 * 100 }, (error, stdout, stderr) => {
      if (signal?.aborted) {
        reject(new Error('任务已被取消'));
        return;
      }
      if (error) {
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });

    if (signal) {
      const onAbort = () => {
        if (!child.killed) {
          child.kill('SIGTERM');
        }
        reject(new Error('任务已被取消'));
      };

      signal.addEventListener('abort', onAbort, { once: true });
      child.on('exit', () => {
        signal.removeEventListener('abort', onAbort);
      });
    }
  });
}

// 缓存与流式下载图片 Buffer（彻底规避 Telegram WEBPAGE_CURL_FAILED 错误）
async function fetchImageBuffer(url: string, referer = 'https://www.pixiv.net/', signal?: AbortSignal): Promise<Buffer | null> {
  if (!url) return null;
  if (signal?.aborted) return null;
  try {
    const res = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: getPixivHeaders(referer),
      timeout: 15000,
      signal,
    });
    return Buffer.from(res.data);
  } catch (error: any) {
    if (signal?.aborted || error?.code === 'ERR_CANCELED' || error?.message === '任务已被取消') {
      return null;
    }
    return null;
  }
}

function extractPixivId(text: string): string | null {
  if (!text) return null;
  const match = text.match(/(?:artworks\/|illust_id=|i\/|pixiv\.net\/[^\d]*|\b)([0-9]{6,12})\b/i);
  return match ? match[1] : null;
}

function formatArtworkCaption(illust: any): string {
  const title = illust.title || illust.illustTitle || '无标题';
  const authorName = illust.userName || illust.author?.name || '未知画师';
  const authorId = illust.userId || illust.author?.id || '';
  const id = illust.id || illust.illustId;
  const isR18 = illust.xRestrict === 1 || illust.xRestrict === 2;
  const tags = (illust.tags?.tags || illust.tags || [])
    .map((t: any) => `#${escapeHtml((typeof t === 'string' ? t : t.tag).replace(/[\s\-]/g, '_'))}`)
    .join(' ');

  return [
    `🎨 <b>${escapeHtml(title)}</b> ${isR18 ? '🔞 [R-18]' : ''}`,
    `👤 画师: <a href="https://www.pixiv.net/users/${authorId}">${escapeHtml(authorName)}</a>`,
    `🆔 作品 ID: <code>${id}</code> | 页数: <b>${illust.pageCount || 1}P</b>`,
    illust.width && illust.height ? `📐 尺寸: ${illust.width}x${illust.height}` : '',
    tags ? `🏷️ ${tags}` : '',
    `🔗 <a href="https://www.pixiv.net/artworks/${id}">在 Pixiv 原站查看</a>`
  ].filter(Boolean).join('\n');
}

function escapeHtml(text: string): string {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function fetchArtworkDetails(illustId: string, signal?: AbortSignal): Promise<any> {
  if (signal?.aborted) {
    throw new Error('任务已被取消');
  }

  let ajaxFailure = 'Pixiv Ajax 未返回作品详情';
  try {
    const res = await axios.get(`https://www.pixiv.net/ajax/illust/${illustId}`, {
      headers: getPixivHeaders(`https://www.pixiv.net/artworks/${illustId}`),
      timeout: 10000,
      signal,
    });
    const details = res.data?.body;
    if (details && Number(details.pageCount) > 0 && Number.isFinite(Number(details.illustType))) {
      return details;
    }
    ajaxFailure = res.data?.message || 'Pixiv Ajax 未返回有效的页数和作品类型';
  } catch (err: any) {
    if (signal?.aborted || err?.code === 'ERR_CANCELED' || err?.message === '任务已被取消') {
      throw new Error('任务已被取消');
    }
    ajaxFailure = `Pixiv Ajax 请求失败${err?.response?.status ? `（HTTP ${err.response.status}）` : ''}`;
  }

  try {
    const page = await axios.get(`https://www.pixiv.net/artworks/${illustId}`, {
      headers: getPixivHeaders(`https://www.pixiv.net/`),
      timeout: 15000,
      signal,
      responseType: 'text'
    });
    const metaTag = String(page.data).match(/<meta\b[^>]*id=["']meta-preload-data["'][^>]*>/i)?.[0];
    const content = metaTag?.match(/\bcontent=(["'])(.*?)\1/i)?.[2];
    if (content) {
      const preloadData = JSON.parse(content
        .replace(/&quot;/g, '"')
        .replace(/&#x27;|&#39;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&'));
      const details = preloadData?.illust?.[illustId];
      if (details && Number(details.pageCount) > 0 && Number.isFinite(Number(details.illustType))) {
        console.warn(`Pixiv Ajax 详情不可用，已从作品页面恢复作品 #${illustId} 的元数据`);
        return details;
      }
    }
  } catch (err: any) {
    if (signal?.aborted || err?.code === 'ERR_CANCELED' || err?.message === '任务已被取消') {
      throw new Error('任务已被取消');
    }
    console.warn(`Pixiv 作品页面备用解析失败 (#${illustId}): HTTP ${err?.response?.status || '网络错误'}`);
  }

  throw new Error(`${ajaxFailure}，且无法从 Pixiv 作品页面读取完整元数据。请确认作品可访问，并检查服务器是否被 Pixiv/Cloudflare 限制。`);
}

async function fetchPixivFavoriteIds(userId: string): Promise<string[]> {
  if (!currentPixivCookie) {
    throw new Error('尚未配置 Pixiv Cookie，请先私聊机器人发送 /cookie PHPSESSID');
  }

  const ids = new Set<string>();
  for (const visibility of ['show', 'hide']) {
    let response;
    try {
      response = await axios.get(
        `https://www.pixiv.net/ajax/user/${userId}/illusts/bookmarks?tag=&offset=0&limit=48&rest=${visibility}`,
        {
          headers: getPixivHeaders(`https://www.pixiv.net/users/${userId}/bookmarks/artworks`),
          timeout: 15000
        }
      );
    } catch (error: any) {
      const status = error?.response?.status;
      if (status === 403) {
        throw new Error('Pixiv/Cloudflare 拒绝了当前服务器的请求（HTTP 403）。这通常与服务器出口 IP 或网络有关；请确认 Cookie 仍有效，并稍后重试或联系服务器网络提供商。');
      }
      if (status === 401) {
        throw new Error('Pixiv 登录 Cookie 无效或已过期，请重新配置 Cookie 后重试。');
      }
      throw new Error(`请求 Pixiv 收藏列表失败${status ? `（HTTP ${status}）` : ''}：${error?.message || '网络错误'}`);
    }

    const body = response.data?.body;
    if (typeof response.data === 'string' && /cloudflare|just a moment|cf_chl/i.test(response.data)) {
      throw new Error('Pixiv/Cloudflare 返回了访问验证页面，当前服务器请求被拦截。请稍后重试或联系服务器网络提供商。');
    }
    if (response.data?.error || !Array.isArray(body?.works)) {
      throw new Error(`Pixiv 未返回${visibility === 'show' ? '公开' : '私密'}收藏列表；请确认 Cookie 有效且对应账号有权访问该收藏列表。`);
    }
    for (const item of body.works) {
      const id = String(item?.id || item?.illustId || item?.illust?.id || '');
      if (/^\d{1,12}$/.test(id)) ids.add(id);
    }
  }
  return [...ids];
}

async function sendWatchedArtwork(chatId: number, illustId: string, ownerUserId: number): Promise<void> {
  const illust = await fetchArtworkDetails(illustId);
  const caption = formatArtworkCaption(illust);

  if (illust.illustType === 2) {
    if (IS_VERCEL) {
      await bot.api.sendMessage(
        chatId,
        `${caption}\n\n⚠️ Vercel 部署不提供 FFmpeg 动图转码，请前往 Pixiv 查看原作品。`,
        { parse_mode: 'HTML' }
      );
      return;
    }

    const owner = userStatusMap.get(ownerUserId);
    if (!userCanUseUgoira({ id: ownerUserId, username: owner?.username })) {
      throw new Error('绑定用户没有动图解析权限，请联系管理员授权');
    }
    const result = await convertUgoira(illustId, 'mp4');
    if (!result.ok) throw new Error(result.error);
    try {
      await bot.api.sendVideo(chatId, new InputFile(result.filePath), {
        caption,
        parse_mode: 'HTML',
        duration: result.duration
      });
      await relayToConfiguredChats({ api: bot.api }, chatId, async (targetChatId) => {
        await bot.api.sendVideo(targetChatId, new InputFile(result.filePath), {
          caption,
          parse_mode: 'HTML',
          duration: result.duration
        });
      });
    } finally {
      fs.rmSync(path.dirname(result.filePath), { recursive: true, force: true });
    }
    return;
  }

  const totalPages = Math.max(1, Number(illust.pageCount) || 1);
  if (totalPages === 1) {
    const originalUrl = illust.urls?.original;
    const image = (originalUrl && await fetchImageBuffer(originalUrl, `https://www.pixiv.net/artworks/${illustId}`)) ||
      await fetchImageBuffer(`https://pixiv.cat/${illustId}.jpg`);
    if (!image) throw new Error('无法下载作品图片');
    await bot.api.sendPhoto(chatId, new InputFile(image, `${illustId}.jpg`), {
      caption,
      parse_mode: 'HTML'
    });
    await relayToConfiguredChats({ api: bot.api }, chatId, async (targetChatId) => {
      await bot.api.sendPhoto(targetChatId, new InputFile(image, `${illustId}.jpg`), {
        caption,
        parse_mode: 'HTML'
      });
    });
    return;
  }

  const pageLimit = sendAllImagesMode ? totalPages : Math.min(totalPages, 10);
  for (let batchStart = 0; batchStart < pageLimit; batchStart += 10) {
    const batchEnd = Math.min(pageLimit, batchStart + 10);
    const photos: BufferedAlbumPhoto[] = [];
    for (let page = batchStart; page < batchEnd; page++) {
      const pageOriginal = illust.urls?.original?.replace(/_p0\./, `_p${page}.`);
      const image = (pageOriginal && await fetchImageBuffer(pageOriginal, `https://www.pixiv.net/artworks/${illustId}`)) ||
        await fetchImageBuffer(`https://pixiv.cat/${illustId}-${page + 1}.jpg`);
      if (!image) continue;
      photos.push({
        buffer: image,
        filename: `${illustId}_p${page}.jpg`,
        caption: batchStart === 0 && photos.length === 0 ? caption : undefined,
        parse_mode: batchStart === 0 && photos.length === 0 ? 'HTML' : undefined
      });
    }
    if (!photos.length) continue;

    await sendBufferedPhotoAlbum(
      photos,
      (media) => bot.api.sendMediaGroup(chatId, media),
      (photo, options) => bot.api.sendPhoto(chatId, photo, options),
      (document, options) => bot.api.sendDocument(chatId, document, options)
    );
    await relayToConfiguredChats({ api: bot.api }, chatId, async (targetChatId) => {
      await sendBufferedPhotoAlbum(
        photos,
        (media) => bot.api.sendMediaGroup(targetChatId, media),
        (photo, options) => bot.api.sendPhoto(targetChatId, photo, options),
        (document, options) => bot.api.sendDocument(targetChatId, document, options)
      );
    });
  }

  const status = sendAllImagesMode
    ? `✅ 已自动发送全部图片`
    : `默认模式已发送第 1 批，剩余图片可通过按钮获取`;
  const statusText = `📚 <b>${escapeHtml(illust.title || illustId)}</b>（共 ${totalPages}P）\n${status}`;
  const statusOptions = {
    parse_mode: 'HTML' as const,
    reply_markup: buildBatchKeyboard(illustId, 0, Math.ceil(totalPages / 10), totalPages)
  };
  await bot.api.sendMessage(chatId, statusText, statusOptions);
  await relayTextToConfiguredChats({ api: bot.api }, chatId, statusText, statusOptions);
}

let pixivFavoritePollRunning = false;
let pixivFavoriteLastError = '';

export async function pollPixivFavorites(): Promise<{ checked: boolean; newCount: number; error?: string }> {
  if (pixivFavoritePollRunning || !pixivFavoriteWatch || !currentPixivCookie) {
    return { checked: false, newCount: 0 };
  }
  pixivFavoritePollRunning = true;
  let processedCount = 0;
  try {
    const watch = pixivFavoriteWatch;
    const watchVersion = pixivFavoriteWatchVersion;
    const favoriteIds = await fetchPixivFavoriteIds(watch.pixivUserId);
    const knownIds = new Set(watch.knownIllustIds);
    const newIds = favoriteIds.filter((id) => !knownIds.has(id)).reverse();

    for (const illustId of newIds) {
      if (watchVersion !== pixivFavoriteWatchVersion) break;
      await sendWatchedArtwork(watch.chatId, illustId, watch.ownerUserId);
      if (watchVersion !== pixivFavoriteWatchVersion) break;
      watch.knownIllustIds.push(illustId);
      watch.knownIllustIds = watch.knownIllustIds.slice(-MAX_TRACKED_FAVORITE_IDS);
      savePixivFavoriteWatch();
      console.log(`✅ 已自动解析 Pixiv 新收藏作品 #${illustId}`);
      processedCount++;
    }
    pixivFavoriteLastError = '';
    return { checked: true, newCount: processedCount };
  } catch (error: any) {
    pixivFavoriteLastError = error.message || '未知错误';
    console.error('轮询 Pixiv 收藏失败:', pixivFavoriteLastError);
    return { checked: true, newCount: processedCount, error: pixivFavoriteLastError };
  } finally {
    pixivFavoritePollRunning = false;
  }
}

bot.command('watchpixiv', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能绑定 Pixiv 收藏监控。');
    return;
  }
  if (ctx.chat.type !== 'private') {
    await ctx.reply('🔐 请在与机器人的私聊中设置收藏监控，避免把作品发送到群组。');
    return;
  }
  if (!currentPixivCookie) {
    await ctx.reply('⚠️ 尚未配置 Pixiv Cookie。请先私聊发送 <code>/cookie PHPSESSID</code>，再设置监控。', {
      parse_mode: 'HTML'
    });
    return;
  }
  if (pixivFavoritePollRunning) {
    await ctx.reply('⏳ 收藏检查正在进行，请稍后再更改监控设置。');
    return;
  }

  const pixivUserId = (ctx.message?.text || '').trim().split(/\s+/)[1] || '';
  if (!/^\d{1,12}$/.test(pixivUserId)) {
    await ctx.reply(
      '📌 用法：<code>/watchpixiv Pixiv用户ID</code>\n' +
      '发送你 Pixiv 个人主页链接中的数字 ID。请确保已配置的 Cookie 登录的是这个账号。\n' +
      '启用时会把现有收藏设为基线，只自动处理之后新增的收藏。',
      { parse_mode: 'HTML' }
    );
    return;
  }

  try {
    const baselineIds = await fetchPixivFavoriteIds(pixivUserId);
    const previousWatch = pixivFavoriteWatch;
    pixivFavoriteWatch = {
      pixivUserId,
      chatId: ctx.chat.id,
      ownerUserId: ctx.from.id,
      knownIllustIds: baselineIds.slice(-MAX_TRACKED_FAVORITE_IDS)
    };
    try {
      savePixivFavoriteWatch();
    } catch (error) {
      pixivFavoriteWatch = previousWatch;
      throw error;
    }
    pixivFavoriteWatchVersion++;
    pixivFavoriteLastError = '';
    await ctx.reply(
      `✅ 已绑定 Pixiv 账号 <code>${pixivUserId}</code>。\n` +
      `已记录 ${baselineIds.length} 个近期收藏作为基线；之后${PIXIV_FAVORITE_POLL_DESCRIPTION}检查新增收藏并自动解析发送。\n` +
      `自动解析结果仅发送到此私聊。发送 <code>/unwatchpixiv</code> 可停止监控，<code>/watchstatus</code> 查看状态。`,
      { parse_mode: 'HTML' }
    );
  } catch (error: any) {
    console.error('设置 Pixiv 收藏监控失败:', error.message || '未知错误');
    await ctx.reply(`❌ 绑定失败：${escapeHtml(error.message || 'Pixiv 收藏接口请求失败')}`, {
      parse_mode: 'HTML'
    });
  }
});

bot.command('unwatchpixiv', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能停止 Pixiv 收藏监控。');
    return;
  }
  if (!pixivFavoriteWatch) {
    await ctx.reply('ℹ️ 当前没有启用 Pixiv 收藏监控。');
    return;
  }
  const previousWatch = pixivFavoriteWatch;
  pixivFavoriteWatch = null;
  try {
    savePixivFavoriteWatch();
  } catch (error: any) {
    pixivFavoriteWatch = previousWatch;
    console.error('停止 Pixiv 收藏监控失败:', error);
    await ctx.reply(`❌ 停止监控失败：${escapeHtml(error.message || '无法保存配置')}`);
    return;
  }
  pixivFavoriteWatchVersion++;
  await ctx.reply('🛑 已停止 Pixiv 收藏监控。');
});

bot.command('watchstatus', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能查看 Pixiv 收藏监控状态。');
    return;
  }
  if (!pixivFavoriteWatch) {
    await ctx.reply('📭 当前没有启用 Pixiv 收藏监控。使用 <code>/watchpixiv Pixiv用户ID</code> 绑定。', {
      parse_mode: 'HTML'
    });
    return;
  }

  const watch = pixivFavoriteWatch;
  await ctx.reply(
    `📡 <b>Pixiv 收藏监控</b>\n\n` +
    `• Pixiv 用户 ID：<code>${watch.pixivUserId}</code>\n` +
    `• 检查频率：${PIXIV_FAVORITE_POLL_DESCRIPTION}\n` +
    `• 状态：${currentPixivCookie ? '运行中' : '暂停（未配置 Cookie）'}\n` +
    (pixivFavoriteLastError ? `• 最近错误：${escapeHtml(pixivFavoriteLastError)}\n` : ''),
    { parse_mode: 'HTML' }
  );
});

bot.command('checkpixiv', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能手动检查 Pixiv 收藏。');
    return;
  }
  if (!pixivFavoriteWatch) {
    await ctx.reply('📭 尚未启用收藏监控，请先发送 <code>/watchpixiv Pixiv用户ID</code>。', {
      parse_mode: 'HTML'
    });
    return;
  }
  if (!currentPixivCookie) {
    await ctx.reply('⚠️ 尚未配置 Pixiv Cookie，请先发送 <code>/cookie PHPSESSID</code>。', {
      parse_mode: 'HTML'
    });
    return;
  }
  if (pixivFavoritePollRunning) {
    await ctx.reply('⏳ 收藏检查已经在运行中，请稍后查看结果。');
    return;
  }

  await ctx.reply('🔎 正在立即检查 Pixiv 新收藏，请稍候...');
  const result = await pollPixivFavorites();
  if (!result.checked) {
    await ctx.reply('⏳ 暂时无法开始检查，请稍后重试。');
    return;
  }
  if (result.error) {
    await ctx.reply(`❌ 检查失败：${escapeHtml(result.error)}`);
    return;
  }
  await ctx.reply(result.newCount > 0
    ? `✅ 检查完成，发现并发送了 ${result.newCount} 个新收藏作品。`
    : '✅ 检查完成，没有发现新的收藏作品。');
});

const MAX_UGOIRA_FILE_SIZE = 50 * 1024 * 1024;
const MP4_RENDER_FILTER = "scale='min(1920,iw)':-2:flags=lanczos,setsar=1,scale=trunc(iw/2)*2:trunc(ih/2)*2";

// 将 Ugoira 动图下载并转换为 MP4 / GIF (优先保持在 50MB 内高质量渲染，超过则按保守压缩处理)
async function convertUgoira(illustId: string, outputType: 'mp4' | 'gif', signal?: AbortSignal): Promise<{ ok: true; filePath: string; duration: number } | { ok: false; isCookieMissing: boolean; error: string }> {
  if (IS_VERCEL) {
    return { ok: false, isCookieMissing: false, error: 'Vercel 部署版本暂不支持 FFmpeg 动图转码' };
  }

  if (signal?.aborted) {
    return { ok: false, isCookieMissing: false, error: '任务已被取消' };
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `ugoira-${illustId}-`));
  const zipPath = path.join(tmpDir, 'ugoira.zip');
  const extractDir = path.join(tmpDir, 'frames');
  const outputPath = path.join(tmpDir, `result.${outputType}`);

  try {
    // 1. 获取 Ugoira 元数据 (帧间隔与时间)
    let metaRes: any;
    try {
      metaRes = await axios.get(`https://www.pixiv.net/ajax/illust/${illustId}/ugoira_meta`, {
        headers: getPixivHeaders(`https://www.pixiv.net/artworks/${illustId}`),
        timeout: 15000,
        signal,
      });
    } catch (e: any) {
      if (signal?.aborted || e?.code === 'ERR_CANCELED' || e?.message === '任务已被取消') {
        return { ok: false, isCookieMissing: false, error: '任务已被取消' };
      }
      const is404 = e.response?.status === 404;
      return { ok: false, isCookieMissing: is404, error: is404 ? '需要登录 Cookie 才能获取帧列表' : (e.message || '网络连接超时') };
    }

    const meta = metaRes.data?.body;
    if (!meta || (!meta.src && !meta.originalSrc) || !meta.frames || meta.frames.length === 0) {
      return { ok: false, isCookieMissing: true, error: '未获取到关键帧数据' };
    }

    // 2. 下载 ZIP 压缩包 (优先使用官方 Web 优化流 meta.src，体积小且不丢帧；大文件超时设为 120 秒)
    const downloadUrl = meta.src || meta.originalSrc;
    console.log(`📥 正在下载 Ugoira 动图 ZIP: ${downloadUrl}`);
    const zipDownload = await axios.get(downloadUrl, {
      responseType: 'arraybuffer',
      headers: getPixivHeaders('https://www.pixiv.net/'),
      timeout: 120000,
      signal,
    });
    fs.writeFileSync(zipPath, Buffer.from(zipDownload.data));

    // 3. 解压缩帧文件
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);

    // 4. 构建 FFmpeg concat demuxer 输入清单文件 (按 Pixiv 官方指定每帧精确毫秒延迟)
    const concatFilePath = path.join(tmpDir, 'input.txt');
    let concatContent = '';
    let totalDurationMs = 0;

    for (const frame of meta.frames) {
      const frameDelaySec = (frame.delay || 80) / 1000;
      totalDurationMs += (frame.delay || 80);
      concatContent += `file '${path.join(extractDir, frame.file)}'\n`;
      concatContent += `duration ${frameDelaySec.toFixed(4)}\n`;
    }
    if (meta.frames.length > 0) {
      concatContent += `file '${path.join(extractDir, meta.frames[meta.frames.length - 1].file)}'\n`;
    }
    fs.writeFileSync(concatFilePath, concatContent, 'utf8');

    // 5. 调用 FFmpeg 渲染：优先保留 50MB 内的高质量输出，超出后进行保守压缩。
    if (outputType === 'mp4') {
      const renderSteps = [
        `ffmpeg -y -loglevel warning -f concat -safe 0 -i "${concatFilePath}" -vf "${MP4_RENDER_FILTER}" -c:v libx264 -pix_fmt yuv420p -preset medium -crf 20 -movflags +faststart "${outputPath}"`,
        `ffmpeg -y -loglevel warning -i "${outputPath}" -vf "scale='min(1440,iw)':-2:flags=lanczos,setsar=1,scale=trunc(iw/2)*2:trunc(ih/2)*2" -c:v libx264 -pix_fmt yuv420p -preset medium -crf 24 -movflags +faststart "${path.join(tmpDir, 'compressed_1.mp4')}"`,
        `ffmpeg -y -loglevel warning -i "${outputPath}" -vf "scale='min(960,iw)':-2:flags=lanczos,setsar=1,scale=trunc(iw/2)*2:trunc(ih/2)*2" -c:v libx264 -pix_fmt yuv420p -preset veryfast -crf 28 -movflags +faststart "${path.join(tmpDir, 'compressed_2.mp4')}"`
      ];

      let lastOutput = outputPath;
      let finalSize = MAX_UGOIRA_FILE_SIZE + 1;

      for (let i = 0; i < renderSteps.length; i++) {
        const targetPath = i === 0 ? outputPath : path.join(tmpDir, `compressed_${i}.mp4`);
        const command = renderSteps[i].replace(outputPath, targetPath);
        await runShellCommand(command, signal);

        if (fs.existsSync(targetPath)) {
          finalSize = fs.statSync(targetPath).size;
          if (finalSize <= MAX_UGOIRA_FILE_SIZE) {
            lastOutput = targetPath;
            break;
          }
          lastOutput = targetPath;
        }
      }

      if (finalSize > MAX_UGOIRA_FILE_SIZE) {
        const compressedPath = path.join(tmpDir, 'final_50mb.mp4');
        await runShellCommand(
          `ffmpeg -y -loglevel warning -i "${lastOutput}" -vf "scale='min(720,iw)':-2:flags=lanczos,setsar=1,scale=trunc(iw/2)*2:trunc(ih/2)*2" -c:v libx264 -pix_fmt yuv420p -preset veryfast -crf 30 -movflags +faststart "${compressedPath}"`,
          signal
        );
        if (fs.existsSync(compressedPath)) {
          finalSize = fs.statSync(compressedPath).size;
          if (finalSize <= MAX_UGOIRA_FILE_SIZE) {
            fs.renameSync(compressedPath, outputPath);
          }
        }
      }

      if (fs.existsSync(outputPath) && fs.statSync(outputPath).size > MAX_UGOIRA_FILE_SIZE) {
        throw new Error(`生成的动图文件仍超过 ${MAX_UGOIRA_FILE_SIZE / 1024 / 1024}MB 限制`);
      }
    } else {
      const palettePath = path.join(tmpDir, 'palette.png');
      await runShellCommand(
        `ffmpeg -y -loglevel warning -f concat -safe 0 -i "${concatFilePath}" -vf "fps=15,scale='min(800,iw)':-2:flags=lanczos,palettegen" "${palettePath}"`,
        signal
      );
      await runShellCommand(
        `ffmpeg -y -loglevel warning -f concat -safe 0 -i "${concatFilePath}" -i "${palettePath}" -lavfi "fps=15,scale='min(800,iw)':-2 [x]; [x][1:v] paletteuse" "${outputPath}"`,
        signal
      );
    }

    return { ok: true, filePath: outputPath, duration: Math.max(1, Math.round(totalDurationMs / 1000)) };
  } catch (error: any) {
    if (signal?.aborted || error?.message === '任务已被取消') {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      return { ok: false, isCookieMissing: false, error: '任务已被取消' };
    }
    console.error('Ugoira 转换报错:', error);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    return { ok: false, isCookieMissing: false, error: error.message || '转码处理异常' };
  }
}

// 构建单页逐页翻页键盘 (上一页 / 当前页 / 下一页)
function buildPageKeyboard(illustId: string, currentPage: number, totalPages: number): InlineKeyboard {
  const kb = new InlineKeyboard();

  if (currentPage > 0) {
    kb.text('⬅️ 上一页', `page:${illustId}:${currentPage - 1}:${totalPages}`);
  } else {
    kb.text('⏹️ 首页', 'noop');
  }

  kb.text(`📖 ${currentPage + 1} / ${totalPages}P`, 'noop');

  if (currentPage < totalPages - 1) {
    kb.text('下一页 ➡️', `page:${illustId}:${currentPage + 1}:${totalPages}`);
  } else {
    kb.text('末页 ⏹️', 'noop');
  }
  kb.row();

  if (totalPages > 10) {
    const currentBatch = Math.floor(currentPage / 10);
    const totalBatches = Math.ceil(totalPages / 10);
    kb.text(`📚 批次导航 (第 ${currentBatch + 1}/${totalBatches} 批)`, `batchNav:${illustId}:${currentBatch}:${totalPages}`);
    kb.row();
  }

  kb.text(`⬇️ 下载第 ${currentPage + 1}P 原图`, `doc:${illustId}:${currentPage}`);
  kb.url('🔗 Pixiv 原网', `https://www.pixiv.net/artworks/${illustId}`);

  return kb;
}

function buildPageDownloadButtons(illustId: string, totalPages: number, startPage = 0): InlineKeyboard {
  const kb = new InlineKeyboard();
  const pageStart = startPage;
  const pageEnd = Math.min(totalPages, startPage + 10);

  for (let page = pageStart; page < pageEnd; page++) {
    kb.text(`P${page + 1}`, `doc:${illustId}:${page}`);
    if ((page - pageStart + 1) % 5 === 0) {
      kb.row();
    }
  }

  if ((pageEnd - pageStart) % 5 !== 0) {
    kb.row();
  }

  const currentBatch = Math.floor(pageStart / 10);
  const totalBatches = Math.ceil(totalPages / 10);

  if (pageStart > 0) {
    kb.text('⬅️ 上一批', `pageDownloadBatch:${illustId}:${Math.max(0, pageStart - 10)}:${totalPages}`);
  } else {
    kb.text('⏹️ 首页', 'noop');
  }

  kb.text(`📦 第 ${currentBatch + 1}/${totalBatches} 批`, 'noop');

  if (pageEnd < totalPages) {
    kb.text('下一批 ➡️', `pageDownloadBatch:${illustId}:${pageEnd}:${totalPages}`);
  } else {
    kb.text('末页 ⏹️', 'noop');
  }
  kb.row();

  kb.text('📥 获取全部', `all:${illustId}:${totalPages}`);
  kb.row();

  kb.text(`⬇️ 下载第 ${pageStart + 1}P 原图`, `doc:${illustId}:${pageStart}`);
  kb.url('🔗 Pixiv 原网', `https://www.pixiv.net/artworks/${illustId}`);
  return kb;
}

// 构建整批相册翻页键盘 (上一批 / 下一批)
function buildBatchKeyboard(illustId: string, currentBatch: number, totalBatches: number, totalPages: number): InlineKeyboard {
  const kb = new InlineKeyboard();
  const startP = currentBatch * 10 + 1;
  const endP = Math.min(totalPages, (currentBatch + 1) * 10);

  for (let page = startP - 1; page < endP; page++) {
    kb.text(`P${page + 1}`, `doc:${illustId}:${page}`);
    if ((page - (startP - 1) + 1) % 5 === 0) {
      kb.row();
    }
  }

  if ((endP - (startP - 1)) % 5 !== 0) {
    kb.row();
  }

  if (currentBatch > 0) {
    kb.text('⬅️ 上一批', `album:${illustId}:${currentBatch - 1}:${totalPages}`);
  } else {
    kb.text('⏹️ 首页', 'noop');
  }

  kb.text(`📦 第 ${currentBatch + 1} / ${totalBatches} 批`, 'noop');

  if (currentBatch < totalBatches - 1) {
    kb.text('下一批 ➡️', `album:${illustId}:${currentBatch + 1}:${totalPages}`);
  } else {
    kb.text('末页 ⏹️', 'noop');
  }
  kb.row();

  kb.text('📥 获取全部', `all:${illustId}:${totalPages}`);
  kb.text('📦 ZIP 下载', `zip:${illustId}`);
  kb.row();

  kb.text(`⬇️ 下载第 ${startP}P 原图`, `doc:${illustId}:${startP - 1}`);
  kb.url('🔗 Pixiv 原网', `https://www.pixiv.net/artworks/${illustId}`);

  return kb;
}

function buildZipKeyboard(illustId: string): InlineKeyboard {
  const kb = new InlineKeyboard();
  kb.text('📦 下载整作品 ZIP', `zip:${illustId}`);
  kb.url('🔗 Pixiv 原网', `https://www.pixiv.net/artworks/${illustId}`);
  return kb;
}

bot.command('start', async (ctx) => {
  const commonCommands = [
    '• <code>/start</code> — 查看命令列表',
    '• <code>/help</code> — 查看使用帮助',
    '• <code>/password 密码</code> — 验证机器人访问权限（私聊）',
    '• <code>/queue</code> — 查看任务队列',
    '• <code>/status</code> — 查看当前任务状态',
    '• <code>/cancel</code> — 取消排队任务',
    '• <code>/stop</code> — 停止当前解析任务',
    '• <code>/chatid</code> / <code>/groupid</code> — 查看当前聊天 ID',
    '• <code>/sub 画师ID</code> — 订阅画师更新',
    '• <code>/unsub 画师ID</code> — 取消画师订阅',
    '• <code>/subs</code> — 查看已订阅画师',
    '• <code>/cookie</code> — 查看 Pixiv Cookie 状态',
    '• <code>/cookie PHPSESSID</code> — 配置 Pixiv Cookie',
    '• <code>/cookie clear</code> — 清除 Pixiv Cookie'
  ];
  const adminCommands = [
    '• <code>/watchpixiv Pixiv用户ID</code> — 监控新收藏',
    '• <code>/unwatchpixiv</code> — 停止收藏监控',
    '• <code>/watchstatus</code> — 查看收藏监控状态',
    '• <code>/checkpixiv</code> — 立即检查新收藏',
    '• <code>/no</code> / <code>/off</code> — 开启 / 关闭多图全部发送',
    '• <code>/ls</code> — 查看用户状态',
    '• <code>/root 用户名</code> — 授权用户',
    '• <code>/revoke 用户名</code> — 取消用户授权',
    '• <code>/kill 用户名</code> — 封禁用户',
    '• <code>/run 用户名</code> — 解除用户封禁'
  ];
  const isAdmin = isAdminUsername(ctx.from?.username);

  await ctx.reply(
    `👋 <b>欢迎使用 Pixiv 原画 & 动图解析下载机器人！</b>\n\n` +
    `• 发送 Pixiv 分享链接或作品 ID 即可解析\n` +
    `• 支持多图相册、动图 MP4 与原图下载\n\n` +
    `<b>常用命令</b>\n${commonCommands.join('\n')}\n\n` +
    (isAdmin ? `<b>管理员命令</b>\n${adminCommands.join('\n')}` : ''),
    { parse_mode: 'HTML' }
  );
});

bot.command('help', async (ctx) => {
  await ctx.reply(
    `💡 <b>Pixiv Bot 使用帮助:</b>\n\n` +
    `• 发送分享链接即自动解析下载\n` +
    `• 多图作品支持【上一页/下一页】与【上一批/下一批】相册\n` +
    `• 发送 <code>/stop</code> 可中断当前解析任务\n` +
    `• 发送 <code>/queue</code> 查看任务队列\n` +
    `• 发送 <code>/status</code> 查看当前状态\n` +
    `• 发送 <code>/cancel</code> 取消当前任务\n` +
    `• 解析结果会同步转发到 .env 中配置的群组\n` +
    `• 发送 <code>/sub 画师ID</code> 订阅画师更新\n` +
    `• 发送 <code>/subs</code> 列出已订阅画师\n` +
    `• 发送 <code>/cookie</code> 可在线配置 Pixiv Cookie\n` +
    `• 管理员可用 <code>/watchpixiv 用户ID</code> 监控新收藏，<code>/unwatchpixiv</code> 停止，<code>/watchstatus</code> 查看状态\n` +
    `• 管理员可用 <code>/checkpixiv</code> 立即检查 Pixiv 新收藏\n` +
    `• 管理员可用 <code>/no</code> 开启多图自动全部发送，<code>/off</code> 恢复默认分批模式\n` +
    `• 管理员命令：<code>/root @用户名</code> / <code>/revoke @用户名</code> / <code>/kill @用户名</code> / <code>/run @用户名</code> / <code>/ls</code>`,
    { parse_mode: 'HTML' }
  );
});

bot.command('no', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能切换多图片发送模式。');
    return;
  }

  sendAllImagesMode = true;
  await ctx.reply('✅ 已开启多图全部发送模式。接下来解析的多图作品将自动发送全部图片（按批次发送）。');
});

bot.command('off', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能切换多图片发送模式。');
    return;
  }

  sendAllImagesMode = false;
  await ctx.reply('✅ 已关闭多图全部发送模式，接下来解析的多图作品将恢复默认分批发送。');
});

bot.command('ls', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能查看用户状态列表。');
    return;
  }

  const rows = Array.from(userStatusMap.values()).sort((a, b) => a.username.localeCompare(b.username));

  if (!rows.length) {
    await ctx.reply('📭 当前还没有任何已注册用户。');
    return;
  }

  const lines = rows.map((entry) => {
    const chips = [
      entry.isAdmin ? 'admin' : '',
      entry.passwordVerified ? 'pwd' : '',
      entry.rootGranted ? 'root' : '',
      entry.blocked ? 'blocked' : ''
    ].filter(Boolean).join(' | ') || 'guest';
    return `• @${escapeHtml(entry.username)}  →  ${chips}`;
  });

  await ctx.reply(`📋 <b>用户状态列表</b>\n\n${lines.join('\n')}`, { parse_mode: 'HTML' });
});

bot.command('root', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能授权用户。');
    return;
  }

  const text = ctx.message?.text || '';
  const match = text.match(/^\/root(?:@\w+)?\s+(?:@\s*)?([A-Za-z0-9_]{1,32})$/i)
    || text.match(/^\/root(?:@\w+)?\s+(?:@)?([A-Za-z0-9_]{1,32})/i);
  const username = match?.[1] || text.trim().split(/\s+/).slice(1).join(' ').replace(/^@/, '').trim();
  const targetName = normalizeUsername(username);

  if (!targetName) {
    await ctx.reply('📌 用法：<code>/root @用户名</code>', { parse_mode: 'HTML' });
    return;
  }

  const target = await resolveTargetUserByUsername(ctx, targetName);
  if (!target) {
    await ctx.reply(`⚠️ 未找到用户 <code>@${escapeHtml(targetName)}</code>。请确认该用户已在当前会话中出现过，或使用已知用户名。`, { parse_mode: 'HTML' });
    return;
  }

  authorizedUserIds.add(target.id);
  rootGrantedUserIds.add(target.id);
  blockedUserIds.delete(target.id);
  saveAccessStateToDisk();
  syncUserStatus({ id: target.id, username: target.username });
  await ctx.reply(`✅ 已授权用户 <code>@${escapeHtml(target.username)}</code> 使用动图解析功能，并启用标准访问权限。`, { parse_mode: 'HTML' });
});

bot.command('revoke', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能取消授权。');
    return;
  }

  const text = ctx.message?.text || '';
  const match = text.match(/^\/revoke(?:@\w+)?\s+(?:@\s*)?([A-Za-z0-9_]{1,32})$/i)
    || text.match(/^\/revoke(?:@\w+)?\s+(?:@)?([A-Za-z0-9_]{1,32})/i);
  const username = match?.[1] || text.trim().split(/\s+/).slice(1).join(' ').replace(/^@/, '').trim();
  const targetName = normalizeUsername(username);

  if (!targetName) {
    await ctx.reply('📌 用法：<code>/revoke @用户名</code>', { parse_mode: 'HTML' });
    return;
  }

  const target = await resolveTargetUserByUsername(ctx, targetName);
  if (!target) {
    await ctx.reply(`⚠️ 未找到用户 <code>@${escapeHtml(targetName)}</code>。`, { parse_mode: 'HTML' });
    return;
  }

  rootGrantedUserIds.delete(target.id);
  authorizedUserIds.delete(target.id);
  saveAccessStateToDisk();
  syncUserStatus({ id: target.id, username: target.username });
  await ctx.reply(`✅ 已取消用户 <code>@${escapeHtml(target.username)}</code> 的授权。`, { parse_mode: 'HTML' });
});

bot.command('kill', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能封禁用户。');
    return;
  }

  const text = ctx.message?.text || '';
  const match = text.match(/^\/kill(?:@\w+)?\s+(?:@\s*)?([A-Za-z0-9_]{1,32})$/i)
    || text.match(/^\/kill(?:@\w+)?\s+(?:@)?([A-Za-z0-9_]{1,32})/i);
  const username = match?.[1] || text.trim().split(/\s+/).slice(1).join(' ').replace(/^@/, '').trim();
  const targetName = normalizeUsername(username);

  if (!targetName) {
    await ctx.reply('📌 用法：<code>/kill @用户名</code>', { parse_mode: 'HTML' });
    return;
  }

  const target = await resolveTargetUserByUsername(ctx, targetName);
  if (!target) {
    await ctx.reply(`⚠️ 未找到用户 <code>@${escapeHtml(targetName)}</code>。`, { parse_mode: 'HTML' });
    return;
  }

  if (isAdminUsername(target.username)) {
    await ctx.reply('⚠️ 管理员账号不能被封禁。');
    return;
  }

  blockedUserIds.add(target.id);
  rootGrantedUserIds.delete(target.id);
  authorizedUserIds.delete(target.id);
  saveAccessStateToDisk();
  syncUserStatus({ id: target.id, username: target.username });
  await ctx.reply(`🚫 已封禁用户 <code>@${escapeHtml(target.username)}</code>。`, { parse_mode: 'HTML' });
});

bot.command('run', async (ctx) => {
  if (!ctx.from || !isAdminUsername(ctx.from.username)) {
    await ctx.reply('🚫 只有管理员才能解除封禁。');
    return;
  }

  const text = ctx.message?.text || '';
  const match = text.match(/^\/run(?:@\w+)?\s+(?:@\s*)?([A-Za-z0-9_]{1,32})$/i)
    || text.match(/^\/run(?:@\w+)?\s+(?:@)?([A-Za-z0-9_]{1,32})/i);
  const username = match?.[1] || text.trim().split(/\s+/).slice(1).join(' ').replace(/^@/, '').trim();
  const targetName = normalizeUsername(username);

  if (!targetName) {
    await ctx.reply('📌 用法：<code>/run @用户名</code>', { parse_mode: 'HTML' });
    return;
  }

  const target = await resolveTargetUserByUsername(ctx, targetName);
  if (!target) {
    await ctx.reply(`⚠️ 未找到用户 <code>@${escapeHtml(targetName)}</code>。`, { parse_mode: 'HTML' });
    return;
  }

  blockedUserIds.delete(target.id);
  saveAccessStateToDisk();
  syncUserStatus({ id: target.id, username: target.username });
  await ctx.reply(`✅ 已解封用户 <code>@${escapeHtml(target.username)}</code>。`, { parse_mode: 'HTML' });
});

bot.command('chatid', async (ctx) => {
  await ctx.reply(`💬 当前聊天 ID：<code>${ctx.chat.id}</code>`, { parse_mode: 'HTML' });
});

bot.command('groupid', async (ctx) => {
  await ctx.reply(`👥 当前群组 ID：<code>${ctx.chat.id}</code>`, { parse_mode: 'HTML' });
});

bot.command('queue', async (ctx) => {
  const totalQueue = parseTaskQueue.length;
  const current = activeParseTask && activeParseTask.chatId === ctx.chat.id && activeParseTask.userId === (ctx.from?.id ?? 0)
    ? `当前处理中: #${activeParseTask.id}`
    : '当前无你自己的正在处理任务';
  await ctx.reply(`📋 <b>任务队列状态</b>\n\n• 总排队数: <code>${totalQueue}</code>\n• ${current}`, { parse_mode: 'HTML' });
});

bot.command('status', async (ctx) => {
  const userId = ctx.from?.id ?? 0;
  const isActive = activeParseTask && activeParseTask.chatId === ctx.chat.id && activeParseTask.userId === userId;
  const queueCount = parseTaskQueue.filter((task) => task.chatId === ctx.chat.id && task.userId === userId).length;
  await ctx.reply(
    `🟢 <b>当前状态</b>\n\n` +
    `• 处理状态: ${isActive ? '运行中' : '空闲'}\n` +
    `• 你所在聊天的待处理任务: <code>${queueCount}</code>\n` +
    `• 可用命令: <code>/queue</code> / <code>/cancel</code> / <code>/stop</code>`,
    { parse_mode: 'HTML' }
  );
});

bot.command('cancel', async (ctx) => {
  const userId = ctx.from?.id ?? 0;
  const current = activeParseTask && activeParseTask.chatId === ctx.chat.id && activeParseTask.userId === userId;
  const removed = parseTaskQueue.filter((task) => task.chatId === ctx.chat.id && task.userId === userId);

  if (!current && removed.length === 0) {
    await ctx.reply('ℹ️ 当前没有可取消的任务。');
    return;
  }

  if (current) {
    stopCurrentParseTask(ctx.chat.id, userId);
  }

  const nextQueue = parseTaskQueue.filter((task) => !(task.chatId === ctx.chat.id && task.userId === userId));
  for (const task of removed) task.resolve();
  parseTaskQueue.length = 0;
  for (const task of nextQueue) parseTaskQueue.push(task);

  await ctx.reply(`🛑 已取消你当前聊天中的任务，剩余排队数：<code>${parseTaskQueue.length}</code>`, { parse_mode: 'HTML' });
});

bot.command('stop', async (ctx) => {
  const stopped = stopCurrentParseTask(ctx.chat.id, ctx.from?.id ?? 0);
  if (!stopped) {
    await ctx.reply('ℹ️ 当前没有正在解析的任务，或该任务不属于当前聊天。');
    return;
  }

  await ctx.reply('⏹️ 已停止当前解析任务，后续任务将按队列继续执行。');
});

bot.command('sub', async (ctx) => {
  const text = ctx.message?.text || '';
  const args = text.trim().split(/\s+/).slice(1);
  const artistId = args[0]?.trim();
  if (!artistId) {
    await ctx.reply(`📌 用法：<code>/sub 画师ID</code>\n例如：<code>/sub 123456</code>`, { parse_mode: 'HTML' });
    return;
  }

  const added = setSubscription(ctx.chat.id, artistId, args.slice(1).join(' ') || undefined);
  if (!added) {
    await ctx.reply(`ℹ️ 已经订阅过画师 <code>${artistId}</code> 了。`, { parse_mode: 'HTML' });
    return;
  }

  await ctx.reply(`✅ 已订阅画师 <code>${artistId}</code>，该画师有新作品时会通知你。`, { parse_mode: 'HTML' });
});

bot.command('unsub', async (ctx) => {
  const text = ctx.message?.text || '';
  const artistId = text.trim().split(/\s+/).slice(1).join(' ').trim();
  if (!artistId) {
    await ctx.reply(`📌 用法：<code>/unsub 画师ID</code>`, { parse_mode: 'HTML' });
    return;
  }

  const removed = removeSubscription(ctx.chat.id, artistId);
  await ctx.reply(removed ? `✅ 已取消订阅 <code>${artistId}</code>。` : `ℹ️ 当前没有订阅 <code>${artistId}</code>。`, { parse_mode: 'HTML' });
});

bot.command('subs', async (ctx) => {
  const entries = listSubscriptions(ctx.chat.id);
  if (!entries.length) {
    await ctx.reply('📭 你当前还没有订阅任何画师。\n用法：<code>/sub 画师ID</code>', { parse_mode: 'HTML' });
    return;
  }

  const lines = entries.map((item) => `• <code>${item.artistId}</code>${item.artistName ? ` — ${escapeHtml(item.artistName)}` : ''}`);
  await ctx.reply(`📚 <b>已订阅画师</b>\n\n${lines.join('\n')}`, { parse_mode: 'HTML' });
});

// 在线动态配置或查看 Pixiv Cookie (热生效，免重启容器)
bot.command('cookie', async (ctx) => {
  const text = ctx.message?.text || '';
  const parts = text.trim().split(/\s+/);
  const arg = parts.slice(1).join(' ').trim();

  if (arg.toLowerCase() === 'clear' || arg === '清除' || arg === '删除') {
    currentPixivCookie = '';
    if (fs.existsSync(COOKIE_FILE)) {
      try { fs.unlinkSync(COOKIE_FILE); } catch {}
    }
    await ctx.reply('🗑️ <b>Pixiv Cookie 已成功清除！</b>\n当前已恢复为免登录公开镜像模式。', { parse_mode: 'HTML' });
    return;
  }

  if (arg) {
    let cleanCookie = arg;
    if (!cleanCookie.includes('=')) {
      cleanCookie = `PHPSESSID=${cleanCookie}`;
    }
    currentPixivCookie = cleanCookie;
    try {
      fs.writeFileSync(COOKIE_FILE, cleanCookie, 'utf8');
    } catch (e: any) {
      console.error('写入 Cookie 文件失败:', e);
    }

    if (ctx.message) {
      await ctx.api.deleteMessage(ctx.chat.id, ctx.message.message_id).catch(() => {});
    }

    await ctx.reply(
      `✅ <b>Pixiv Cookie 已成功配置并保存！</b>\n\n` +
      `⚡ <b>即刻生效</b>：无需重启或重新构建 Docker 容器！\n` +
      `🔓 已配置 Pixiv 登录 Cookie，可访问需要登录权限的内容。\n` +
      (IS_VERCEL ? `ℹ️ Vercel 版本不提供 Ugoira FFmpeg 转码。\n\n` : `\n`) +
      `💡 <i>安全提示：包含 Cookie 的消息已自动撤回。若需清除请发送 <code>/cookie clear</code>。</i>`,
      { parse_mode: 'HTML' }
    );
    return;
  }

  const hasCookie = Boolean(currentPixivCookie);
  const statusDisplay = hasCookie
    ? '已配置 (Pixiv 登录 Cookie)'
    : '未配置 (当前仅支持全年龄公开画作)';

  await ctx.reply(
    `🔐 <b>Pixiv Cookie 在线配置中心</b>\n\n` +
    `• <b>当前状态:</b> <code>${statusDisplay}</code>\n\n` +
    `📌 <b>如何设置 Cookie:</b>\n` +
    `发送指令：<code>/cookie 您的PHPSESSID值</code>\n` +
    `例如：<code>/cookie 10381692_a8b9c0d1e2f3...</code>\n\n` +
    `🗑️ <b>如何清除 Cookie:</b>\n` +
    `发送指令：<code>/cookie clear</code>`,
    { parse_mode: 'HTML' }
  );
});

bot.on('message:text', async (ctx) => {
  const text = ctx.message.text;
  const illustId = extractPixivId(text);
  if (!illustId) return;
  const sendAllImages = sendAllImagesMode;

  const parseTask = enqueueParseTask(ctx.chat.id, ctx.from?.id ?? 0, async (signal) => {
    const statusMsg = await ctx.reply(`⏳ 正在解析 Pixiv 作品 <code>#${illustId}</code>...`, {
      parse_mode: 'HTML',
      reply_to_message_id: ctx.message.message_id
    });

    try {
      const illust = await fetchArtworkDetails(illustId, signal);
      if (signal.aborted || illust?.error === '任务已被取消') {
        throw new Error('任务已被取消');
      }

      const caption = formatArtworkCaption(illust);
      const isUgoira = illust.illustType === 2;
      const pageCount = illust.pageCount || 1;

      if (isUgoira && !userCanUseUgoira(ctx.from)) {
        await ctx.api.editMessageText(
          statusMsg.chat.id,
          statusMsg.message_id,
          '🔒 <b>动图解析功能仅对管理员授权用户开放</b>。\n请联系管理员执行 <code>/root @用户名</code> 授权后再试。',
          { parse_mode: 'HTML' }
        );
        return;
      }

      const keyboard = new InlineKeyboard()
        .url('🔗 Pixiv 原网', `https://www.pixiv.net/artworks/${illustId}`);
      if (isUgoira) {
        if (!IS_VERCEL) {
          keyboard.text('⬇️ 下载转码 MP4', `ugoiraMp4:${illustId}`);
        }
      } else {
        keyboard.text('⬇️ 下载无损原图 (文件)', `doc:${illustId}:0`)
          .text('📦 下载整作品 ZIP', `zip:${illustId}`);
      }

      if (isUgoira) {
        await ctx.api.editMessageText(
          statusMsg.chat.id,
          statusMsg.message_id,
          IS_VERCEL
            ? '📄 Vercel 版本不支持 FFmpeg 转码，正在准备作品预览...'
            : `🎞️ 正在从 Pixiv 获取关键帧并使用 FFmpeg 渲染动图 (MP4)...`,
          { parse_mode: 'HTML' }
        );

        const ugoiraResult = await convertUgoira(illustId, 'mp4', signal);

        if (ugoiraResult.ok) {
          try {
            await ctx.replyWithVideo(new InputFile(ugoiraResult.filePath), {
              caption: caption,
              parse_mode: 'HTML',
              duration: ugoiraResult.duration,
              reply_markup: keyboard
            });
            await relayToConfiguredChats(ctx, ctx.chat.id, async (targetChatId) => {
              await ctx.api.sendVideo(targetChatId, new InputFile(ugoiraResult.filePath), {
                caption: caption,
                parse_mode: 'HTML',
                duration: ugoiraResult.duration,
                reply_markup: keyboard
              });
            });
          } catch (sendErr: any) {
            console.warn(`replyWithVideo 发送失败 (${sendErr.message})，降级为文档模式发送 MP4...`);
            await ctx.replyWithDocument(new InputFile(ugoiraResult.filePath, `pixiv_${illustId}_animation.mp4`), {
              caption: caption,
              parse_mode: 'HTML',
              reply_markup: keyboard
            });
            await relayToConfiguredChats(ctx, ctx.chat.id, async (targetChatId) => {
              await ctx.api.sendDocument(targetChatId, new InputFile(ugoiraResult.filePath, `pixiv_${illustId}_animation.mp4`), {
                caption: caption,
                parse_mode: 'HTML',
                reply_markup: keyboard
              });
            });
          }
          fs.rmSync(path.dirname(ugoiraResult.filePath), { recursive: true, force: true });
          await ctx.api.deleteMessage(statusMsg.chat.id, statusMsg.message_id).catch(() => {});
          return;
        } else {
          const failedUgoira = ugoiraResult as Extract<typeof ugoiraResult, { ok: false }>;

          if (failedUgoira.error === '任务已被取消') {
            throw new Error('任务已被取消');
          }

          console.warn(`Ugoira 处理失败 (${failedUgoira.error})，回退为单图预览模式`);
          let failureTip = '';
          if (IS_VERCEL) {
            failureTip = `\n\n⚠️ <i>${escapeHtml(failedUgoira.error)}。请通过下方链接前往 Pixiv 查看原作品。</i>`;
          } else if (failedUgoira.isCookieMissing && !currentPixivCookie) {
            failureTip = `\n\n⚠️ <i>注意：此作品属于 R-18 动态画作，Pixiv 官方需要登录权限。请发送 <code>/cookie 您的PHPSESSID</code> 配置后重试。</i>`;
          } else {
            failureTip = `\n\n⚠️ <i>提示：此动图帧文件较大 (${escapeHtml(failedUgoira.error)})，已为您发送封面预览图。您可点击下方按钮下载原始文件或前往原站查看。</i>`;
          }

          const fallbackBuf = await fetchImageBuffer(`https://pixiv.cat/${illustId}.jpg`, 'https://www.pixiv.net/', signal) ||
                              await fetchImageBuffer(`https://pixiv.cat/${illustId}.gif`, 'https://www.pixiv.net/', signal);

          if (fallbackBuf) {
            await ctx.replyWithPhoto(new InputFile(fallbackBuf, `${illustId}.jpg`), {
              caption: caption + failureTip,
              parse_mode: 'HTML',
              reply_markup: keyboard
            });
            await relayToConfiguredChats(ctx, ctx.chat.id, async (targetChatId) => {
              await ctx.api.sendPhoto(targetChatId, new InputFile(fallbackBuf, `${illustId}.jpg`), {
                caption: caption + failureTip,
                parse_mode: 'HTML',
                reply_markup: keyboard
              });
            });
          } else {
            const fallbackText = caption + failureTip + `\n\n🔗 <a href="https://pixiv.cat/${illustId}.jpg">点击查看镜像图片</a>`;
            await ctx.reply(fallbackText, {
              parse_mode: 'HTML',
              reply_markup: keyboard
            });
            await relayTextToConfiguredChats(ctx, ctx.chat.id, fallbackText, {
              parse_mode: 'HTML',
              reply_markup: keyboard
            });
          }

          await ctx.api.deleteMessage(statusMsg.chat.id, statusMsg.message_id).catch(() => {});
          return;
        }
      }

      await ctx.api.editMessageText(
        statusMsg.chat.id,
        statusMsg.message_id,
        `📥 正在获取原画高清数据并传送至 Telegram...`,
        { parse_mode: 'HTML' }
      );

      if (pageCount === 1) {
        const originalUrl = illust.urls?.original;
        let imgBuf = originalUrl ? await fetchImageBuffer(originalUrl, `https://www.pixiv.net/artworks/${illustId}`, signal) : null;
        if (!imgBuf) {
          imgBuf = await fetchImageBuffer(`https://pixiv.cat/${illustId}.jpg`, 'https://www.pixiv.net/', signal);
        }

        if (imgBuf) {
          await ctx.replyWithPhoto(new InputFile(imgBuf, `${illustId}.jpg`), {
            caption: caption,
            parse_mode: 'HTML',
            reply_markup: keyboard
          });
          await relayToConfiguredChats(ctx, ctx.chat.id, async (targetChatId) => {
            await ctx.api.sendPhoto(targetChatId, new InputFile(imgBuf, `${illustId}.jpg`), {
              caption: caption,
              parse_mode: 'HTML',
              reply_markup: keyboard
            });
          });
        } else {
          const fallbackText = caption + `\n\n🔗 镜像地址: https://pixiv.cat/${illustId}.jpg`;
          await ctx.reply(fallbackText, {
            parse_mode: 'HTML',
            reply_markup: keyboard
          });
          await relayTextToConfiguredChats(ctx, ctx.chat.id, fallbackText, {
            parse_mode: 'HTML',
            reply_markup: keyboard
          });
        }
      } else {
        const totalPages = pageCount;
        const totalBatches = Math.ceil(totalPages / 10);
        const firstBatchCount = Math.min(totalPages, 10);
        const pageLimit = sendAllImages ? totalPages : firstBatchCount;
        let sentPages = 0;

        for (let batchStart = 0; batchStart < pageLimit; batchStart += 10) {
          if (signal.aborted) {
            throw new Error('任务已被取消');
          }
          const batchEnd = Math.min(pageLimit, batchStart + 10);
          const mediaGroup: BufferedAlbumPhoto[] = [];

          for (let i = batchStart; i < batchEnd; i++) {
            if (signal.aborted) {
              throw new Error('任务已被取消');
            }

            const pageOriginal = illust.urls?.original ? illust.urls.original.replace(/_p0\./, `_p${i}.`) : null;
            let pBuf = pageOriginal ? await fetchImageBuffer(pageOriginal, `https://www.pixiv.net/artworks/${illustId}`, signal) : null;
            if (!pBuf) {
              pBuf = await fetchImageBuffer(`https://pixiv.cat/${illustId}-${i + 1}.jpg`, 'https://www.pixiv.net/', signal);
            }

            if (pBuf) {
              mediaGroup.push({
                buffer: pBuf,
                filename: `${illustId}_p${i}.jpg`,
                caption: sentPages === 0 && mediaGroup.length === 0 ? caption : undefined,
                parse_mode: sentPages === 0 && mediaGroup.length === 0 ? 'HTML' as const : undefined
              });
            }
          }

          if (mediaGroup.length === 0) continue;

          await sendBufferedPhotoAlbum(
            mediaGroup,
            (media) => ctx.replyWithMediaGroup(media),
            (photo, options) => ctx.replyWithPhoto(photo, options),
            (document, options) => ctx.replyWithDocument(document, options)
          );
          await relayToConfiguredChats(ctx, ctx.chat.id, async (targetChatId) => {
            await sendBufferedPhotoAlbum(
              mediaGroup,
              (media) => ctx.api.sendMediaGroup(targetChatId, media),
              (photo, options) => ctx.api.sendPhoto(targetChatId, photo, options),
              (document, options) => ctx.api.sendDocument(targetChatId, document, options)
            );
          });
          sentPages += mediaGroup.length;
        }

        if (sentPages > 0) {
          if (totalPages > 10) {
            const sentDescription = sendAllImages
              ? `自动发送完成（成功 ${sentPages} / ${totalPages} 张）`
              : `已发送: 第 <b>1</b> / ${totalBatches} 批 (第 1 - ${firstBatchCount} 张)`;
            const batchText =
              `📚 <b>${escapeHtml(illust.title || illustId)}</b> (全 ${totalPages}P)\n` +
              `${sentDescription}\n` +
              (sendAllImages
                ? `👇 可使用下方按钮重新获取指定批次或下载原图：`
                : `👇 请选择要下载的页码，或继续获取全部：`);
            const batchKeyboard = buildBatchKeyboard(illustId, 0, totalBatches, totalPages);
            await ctx.reply(batchText, {
              parse_mode: 'HTML',
              reply_markup: batchKeyboard
            });
            await relayTextToConfiguredChats(ctx, ctx.chat.id, batchText, {
              parse_mode: 'HTML',
              reply_markup: batchKeyboard
            });
          } else {
            const pageText = sendAllImages
              ? `✅ <b>已自动发送全部图片</b>（成功 ${sentPages} / ${totalPages} 张）\n📖 原图下载面板：`
              : `📖 <b>原图下载面板</b> (全 ${totalPages}P)\n点击下方序号即可下载当前页原图：`;
            const pageKeyboard = buildPageDownloadButtons(illustId, totalPages);
            await ctx.reply(pageText, {
              parse_mode: 'HTML',
              reply_markup: pageKeyboard
            });
            await relayTextToConfiguredChats(ctx, ctx.chat.id, pageText, {
              parse_mode: 'HTML',
              reply_markup: pageKeyboard
            });
          }
        } else {
          const fallbackText = caption + `\n\n🔗 查看画集: https://pixiv.cat/${illustId}-1.jpg`;
          await ctx.reply(fallbackText, {
            parse_mode: 'HTML',
            reply_markup: keyboard
          });
          await relayTextToConfiguredChats(ctx, ctx.chat.id, fallbackText, {
            parse_mode: 'HTML',
            reply_markup: keyboard
          });
        }
      }

      await notifySubscribedArtists(ctx.chat.id, illust).catch(() => {});
      await ctx.api.deleteMessage(statusMsg.chat.id, statusMsg.message_id).catch(() => {});
    } catch (error: any) {
      if (signal.aborted || error.message === '任务已被取消') {
        await ctx.api.deleteMessage(statusMsg.chat.id, statusMsg.message_id).catch(() => {});
        return;
      }

      console.error('解析错误:', error);
      await ctx.api.editMessageText(
        statusMsg.chat.id,
        statusMsg.message_id,
        `❌ <b>解析失败:</b> ${escapeHtml(error.message || '未知异常')}`,
        { parse_mode: 'HTML' }
      );
    }
  });
  if (IS_VERCEL) await parseTask;
});

// 处理内联按钮交互回调 (分页翻页 / 相册批次 / 无损原图下载)
bot.on('callback_query:data', async (ctx) => {
  const data = ctx.callbackQuery.data;
  if (!data) return;

  if (data === 'noop') {
    await ctx.answerCallbackQuery();
    return;
  }

  const callbackChat = ctx.chat;
  if (!callbackChat) {
    await ctx.answerCallbackQuery({ text: '此按钮仅支持在聊天消息中使用。', show_alert: true });
    return;
  }

  // 1. 单页逐页翻页 (上一页 / 下一页)
  if (data.startsWith('page:')) {
    const [, illustId, pageStr, totalPagesStr] = data.split(':');
    const targetPage = parseInt(pageStr, 10);
    const totalPages = parseInt(totalPagesStr, 10) || 1;

    await ctx.answerCallbackQuery({ text: `正在翻至第 ${targetPage + 1} / ${totalPages} 页...` });

    const pUrl = `https://pixiv.cat/${illustId}-${targetPage + 1}.jpg`;
    let imgBuf = await fetchImageBuffer(pUrl);

    if (!imgBuf) {
      await ctx.reply(`⚠️ 加载第 ${targetPage + 1}P 失败，可能需要登录权限或图片正在生成缓存。`);
      return;
    }

    const caption = `🎨 <b>Pixiv #${illustId}</b> · 第 <b>${targetPage + 1} / ${totalPages}</b> 页\n` +
                    `🔗 <a href="https://www.pixiv.net/artworks/${illustId}">在 Pixiv 原站查看</a>`;

    const newKb = buildPageKeyboard(illustId, targetPage, totalPages);

    try {
      await ctx.editMessageMedia(
        {
          type: 'photo',
          media: new InputFile(imgBuf, `${illustId}_p${targetPage}.jpg`),
          caption: caption,
          parse_mode: 'HTML'
        },
        { reply_markup: newKb }
      );
    } catch {
      await ctx.replyWithPhoto(new InputFile(imgBuf, `${illustId}_p${targetPage}.jpg`), {
        caption: caption,
        parse_mode: 'HTML',
        reply_markup: newKb
      });
    }
    return;
  }

  // 2. 整批相册翻页 (上一批 10P / 下一批 10P)
  if (data.startsWith('album:')) {
    const [, illustId, batchStr, totalPagesStr] = data.split(':');
    const targetBatch = parseInt(batchStr, 10);
    const totalPages = parseInt(totalPagesStr, 10) || 1;
    const totalBatches = Math.ceil(totalPages / 10);

    const startIdx = targetBatch * 10;
    const endIdx = Math.min(totalPages, (targetBatch + 1) * 10);

    await ctx.answerCallbackQuery({ text: `正在拉取第 ${targetBatch + 1} 批相册 (第 ${startIdx + 1}-${endIdx}P)...` });

    const waitMsg = await ctx.reply(`⏳ 正在下载并打包第 <b>${targetBatch + 1} / ${totalBatches}</b> 批相册 (第 ${startIdx + 1} - ${endIdx}P)...\\n请稍候...`, { parse_mode: 'HTML' });

    const mediaGroup: BufferedAlbumPhoto[] = [];
    for (let i = startIdx; i < endIdx; i++) {
      const pUrl = `https://pixiv.cat/${illustId}-${i + 1}.jpg`;
      const pBuf = await fetchImageBuffer(pUrl);
      if (pBuf) {
        mediaGroup.push({
          buffer: pBuf,
          filename: `${illustId}_p${i}.jpg`,
          caption: mediaGroup.length === 0 ? `🎨 Pixiv #${illustId} (第 ${startIdx + 1}-${endIdx}P)` : undefined,
          parse_mode: mediaGroup.length === 0 ? 'HTML' as const : undefined
        });
      }
    }

    if (mediaGroup.length > 0) {
      await sendBufferedPhotoAlbum(
        mediaGroup,
        (media) => ctx.replyWithMediaGroup(media),
        (photo, options) => ctx.replyWithPhoto(photo, options),
        (document, options) => ctx.replyWithDocument(document, options)
      );
    }

    await ctx.reply(
      `📚 <b>Pixiv #${illustId}</b> (全 ${totalPages}P)\n` +
      `已发送: 第 <b>${targetBatch + 1}</b> / ${totalBatches} 批 (第 ${startIdx + 1} - ${endIdx} 张)\n` +
      `由机器人解析推送，群主并无无权限`,
      {
        parse_mode: 'HTML',
        reply_markup: buildBatchKeyboard(illustId, targetBatch, totalBatches, totalPages)
      }
    );

    await ctx.api.deleteMessage(waitMsg.chat.id, waitMsg.message_id).catch(() => {});
    return;
  }

  // 3. 获取全部图片（整套图集全量下载）
  if (data.startsWith('all:')) {
    const [, illustId, totalPagesStr] = data.split(':');
    const totalPages = parseInt(totalPagesStr, 10) || 1;

    await ctx.answerCallbackQuery({ text: `正在获取全部 ${totalPages} 页原图...` });

    const waitMsg = await ctx.reply(`⏳ 正在获取 <b>Pixiv #${illustId}</b> 全部 ${totalPages} 页原图，可能需要一点时间...`, {
      parse_mode: 'HTML'
    });

    let currentBatch: BufferedAlbumPhoto[] = [];
    for (let page = 0; page < totalPages; page++) {
      const pUrl = `https://pixiv.cat/${illustId}-${page + 1}.jpg`;
      const pBuf = await fetchImageBuffer(pUrl);
      if (!pBuf) continue;

      currentBatch.push({
        buffer: pBuf,
        filename: `${illustId}_p${page}.jpg`,
        caption: currentBatch.length === 0 ? `🎨 Pixiv #${illustId} · 全部 ${totalPages}P` : undefined,
        parse_mode: currentBatch.length === 0 ? 'HTML' as const : undefined
      });

      if (currentBatch.length === 10) {
        await sendBufferedPhotoAlbum(
          currentBatch,
          (media) => ctx.replyWithMediaGroup(media),
          (photo, options) => ctx.replyWithPhoto(photo, options),
          (document, options) => ctx.replyWithDocument(document, options)
        );
        currentBatch = [];
      }
    }

    if (currentBatch.length > 0) {
      await sendBufferedPhotoAlbum(
        currentBatch,
        (media) => ctx.replyWithMediaGroup(media),
        (photo, options) => ctx.replyWithPhoto(photo, options),
        (document, options) => ctx.replyWithDocument(document, options)
      );
    }

    await ctx.api.deleteMessage(waitMsg.chat.id, waitMsg.message_id).catch(() => {});
    return;
  }

  if (data.startsWith('ugoiraMp4:')) {
    const illustId = data.slice('ugoiraMp4:'.length);
    if (!/^\d{6,12}$/.test(illustId)) {
      await ctx.answerCallbackQuery({ text: '作品 ID 无效', show_alert: true });
      return;
    }
    if (!userCanUseUgoira(ctx.from)) {
      await ctx.answerCallbackQuery({ text: '动图 MP4 下载仅对管理员授权用户开放', show_alert: true });
      return;
    }

    await ctx.answerCallbackQuery({ text: '正在重新转码 MP4...' });
    const waitMsg = await ctx.reply(`🎞️ 正在为 <b>Pixiv #${illustId}</b> 重新转码 MP4 文件，请稍候...`, {
      parse_mode: 'HTML'
    });
    let outputDir: string | undefined;

    try {
      const result = await convertUgoira(illustId, 'mp4');
      if (!result.ok) {
        throw new Error(result.error);
      }
      outputDir = path.dirname(result.filePath);
      const filename = `pixiv_${illustId}_animation.mp4`;
      await ctx.replyWithDocument(new InputFile(result.filePath, filename), {
        caption: `🎞️ Pixiv #${illustId} 转码 MP4`
      });
      await relayToConfiguredChats(ctx, callbackChat.id, async (targetChatId) => {
        await ctx.api.sendDocument(targetChatId, new InputFile(result.filePath, filename), {
          caption: `🎞️ Pixiv #${illustId} 转码 MP4`
        });
      });
    } catch (error: any) {
      console.error(`生成 Ugoira MP4 下载文件失败 (#${illustId}):`, error);
      await ctx.reply(`❌ MP4 下载失败：${escapeHtml(error.message || '未知错误')}`, {
        parse_mode: 'HTML'
      });
    } finally {
      if (outputDir) {
        fs.rmSync(outputDir, { recursive: true, force: true });
      }
      await ctx.api.deleteMessage(waitMsg.chat.id, waitMsg.message_id).catch(() => {});
    }
    return;
  }

  // 4. 整作品 ZIP 下载
  if (data.startsWith('zip:')) {
    const [, illustId] = data.split(':');
    await ctx.answerCallbackQuery({ text: `正在打包整作品 ZIP...` });

    const waitMsg = await ctx.reply(`📦 正在生成 <b>Pixiv #${illustId}</b> 全作品 ZIP，请稍候...`, { parse_mode: 'HTML' });
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `pixiv-zip-${illustId}-`));
    const zipPath = path.join(tmpDir, `${illustId}.zip`);

    try {
      const details = await fetchArtworkDetails(illustId);
      const totalPages = details?.pageCount || 1;
      const zip = new AdmZip();

      for (let page = 0; page < totalPages; page++) {
        const pageUrl = details?.urls?.original?.includes('_p0.')
          ? details.urls.original.replace(/_p0\./, `_p${page}.`)
          : `https://pixiv.cat/${illustId}-${page + 1}.jpg`;

        const buf = await fetchImageBuffer(pageUrl, `https://www.pixiv.net/artworks/${illustId}`);
        if (!buf) continue;
        zip.addFile(`pixiv_${illustId}_p${page + 1}.jpg`, buf);
      }

      if (zip.getEntries().length === 0) {
        throw new Error('未获取到任何页面内容');
      }

      zip.writeZip(zipPath);
      await ctx.replyWithDocument(new InputFile(zipPath, `${illustId}_all_pages.zip`), {
        caption: `📦 Pixiv #${illustId} 整作品 ZIP`,
        parse_mode: 'HTML'
      });
    } catch (e: any) {
      await ctx.reply(`❌ ZIP 打包失败: ${escapeHtml(e.message || '未知错误')}`, { parse_mode: 'HTML' });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      await ctx.api.deleteMessage(waitMsg.chat.id, waitMsg.message_id).catch(() => {});
    }
    return;
  }

  // 5. 批次导航快捷切换
  if (data.startsWith('batchNav:')) {
    const [, illustId, batchStr, totalPagesStr] = data.split(':');
    const currentBatch = parseInt(batchStr, 10);
    const totalPages = parseInt(totalPagesStr, 10) || 1;
    const totalBatches = Math.ceil(totalPages / 10);

    await ctx.answerCallbackQuery();
    await ctx.reply(
      `📦 <b>相册批次导航面板</b> (全 ${totalPages}P)\n选择需要获取的相册批次：`,
      {
        parse_mode: 'HTML',
        reply_markup: buildBatchKeyboard(illustId, currentBatch, totalBatches, totalPages)
      }
    );
    return;
  }

  // 5. 批次分页下载入口
  if (data.startsWith('pageDownloadBatch:')) {
    const [, illustId, startStr, totalPagesStr] = data.split(':');
    const startPage = parseInt(startStr, 10) || 0;
    const totalPages = parseInt(totalPagesStr, 10) || 1;

    await ctx.answerCallbackQuery({ text: `正在显示第 ${startPage + 1} 页起的下载面板...` });
    await ctx.reply(
      `📄 <b>下载页码面板</b> (第 ${startPage + 1} - ${Math.min(totalPages, startPage + 10)}P)
点击下方序号即可下载当前页原图：`,
      {
        parse_mode: 'HTML',
        reply_markup: buildPageDownloadButtons(illustId, totalPages, startPage)
      }
    );
    return;
  }

  // 6. 下载无损原图
  if (data.startsWith('doc:')) {
    const parts = data.split(':');
    const id = parts[1];
    const pageIndex = parts[2] ? parseInt(parts[2], 10) : 0;

    await ctx.answerCallbackQuery({ text: `正在下载第 ${pageIndex + 1}P 无损文档原图...` });
    try {
      const pageSuffix = pageIndex > 0 ? `-${pageIndex + 1}` : '';
      const docBuf = await fetchImageBuffer(`https://pixiv.cat/${id}${pageSuffix}.jpg`);
      if (docBuf) {
        await ctx.replyWithDocument(new InputFile(docBuf, `pixiv_${id}_p${pageIndex}.jpg`), {
          caption: `📄 Pixiv #${id} (第 ${pageIndex + 1}P) 无损原画文档`
        });
      } else {
        await ctx.reply(`❌ 下载失败，作品可能需要 Pixiv 登录权限。`);
      }
    } catch (e: any) {
      await ctx.reply(`❌ 发送原图文件失败: ${e.message}`);
    }
    return;
  }
});

if (!IS_VERCEL) {
  console.log('🚀 Pixiv Telegram Bot 正在启动...');
  bot.start({
    onStart: (botInfo) => {
      console.log(`✅ 机器人 @${botInfo.username} 启动成功，正在轮询监听消息...`);
      void pollPixivFavorites();
    }
  });
  setInterval(() => {
    void pollPixivFavorites();
  }, PIXIV_FAVORITE_POLL_INTERVAL_MS);
}

export { bot };
