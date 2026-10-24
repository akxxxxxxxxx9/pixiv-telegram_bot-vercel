# Pixiv Telegram Downloader & Ugoira Bot 部署指南

本项目是一个专为 Telegram 设计的 **Pixiv 画作解析与动图下载机器人**。只要向机器人发送 Pixiv 的分享链接或作品 ID，机器人将自动获取高清大图、多图相册，或将 **Ugoira 动态图片使用 FFmpeg 无缝转换为 MP4/GIF** 发回给用户。

---

## 🌟 核心特性

1. **全自动链接解析**: 识别 `pixiv.net/artworks/{id}`、`pixiv.me/{id}`、`pixiv.net/i/{id}` 或纯数字 ID。
2. **Ugoira 动图合成**: 自动下载 ZIP 帧序列与毫秒级延迟表，通过 FFmpeg 原生渲染为 H.264 MP4 视频与调色板优化 GIF。
3. **防盗链穿透**: 自动注入 `Referer: https://www.pixiv.net/` 请求头，彻底解决 Telegram 直接发送 `i.pximg.net` 导致的 `403 Forbidden` 报错。
4. **多图相册支持**: 漫画与多图作品自动打包为 Telegram MediaGroup 发送，并提供原画下载入口。
5. **极简部署**: 支持 Docker 容器化一键部署（内置 FFmpeg），不污染宿主机环境。

---

## 🛠️ 第一步：获取 Telegram Bot Token

1. 在 Telegram 中搜索官方机器人 [@BotFather](https://t.me/BotFather) 并点击 `Start`。
2. 发送指令 `/newbot`。
3. 输入你的机器人昵称（例如：`MyPixivDownloaderBot`）。
4. 输入你的机器人用户名（必须以 `bot` 结尾，例如：`mypixiv_download_bot`）。
5. @BotFather 会生成一段 **HTTP API Token**（格式如：`718293849:AAHfkjshd..._s982`）。
6. 将 Token 填入本项目配置中。

---

## 🚀 第二步：在你的服务器上一键部署

### 方式 0：部署 Vercel 版本

Vercel 版本使用 Telegram Webhook，不会启动长轮询；用户授权、订阅、Cookie 和收藏监控配置通过 Upstash Redis 持久化。Ugoira 动图在此版本中只提供 Pixiv 链接/预览，不执行 FFmpeg 转码。

1. 将项目推送到 GitHub。确认 `.env`、`data/`、Token 和 Cookie 没有提交。若之前的 Bot Token 已经暴露，先在 BotFather 撤销并换新。
2. 在 Vercel 选择 **Add New → Project**，导入仓库。Framework Preset 选 **Other**，根目录选项目目录；Build Command 使用 `npm run build`。`vercel.json` 会将 `public/` 作为静态输出目录。
3. 在 Vercel Marketplace 为项目创建并连接一个 **Upstash Redis** 数据库。
4. 在 **Project → Settings → Environment Variables** 为 Production 配置：
   - `TELEGRAM_BOT_TOKEN`：BotFather 提供的 Token。
   - `BOT_PASSWORD`：机器人访问密码。
   - `ADMIN_USERNAME`：管理员 Telegram 用户名（不带 `@`）。
   - `UPSTASH_REDIS_REST_URL`、`UPSTASH_REDIS_REST_TOKEN`：Upstash 数据库连接信息。
   - `TELEGRAM_WEBHOOK_SECRET`：随机生成的 Webhook 密钥。
   - `CRON_SECRET`：另一个随机密钥，用于保护收藏检查接口。
   - `PIXIV_COOKIE`、`GROUP_CHAT_ID`：按需配置。
5. 保存变量并部署。建议使用固定的 Production 域名；每次更换 Bot Token 或 webhook secret 后，都要重新设置 Telegram Webhook。
6. 将 Webhook 指向部署域名。把下面占位内容替换为自己的值，在本机终端执行；不要把真实 Token 写进仓库：

```bash
curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -d "url=https://<YOUR_VERCEL_DOMAIN>/api/telegram" \
  -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>" \
  -d "max_connections=1"
```

验证可查询 Webhook 状态：

```bash
curl "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/getWebhookInfo"
```

收藏监控通过 `/api/cron` 定时检查。仓库默认设置为每天运行一次，兼容 Vercel Hobby 计划；该计划不支持每 5 分钟运行。若使用支持分钟级 Cron 的计划，可将 `vercel.json` 中的 schedule 改为 `*/5 * * * *` 后重新部署。

**限制：** 每次 Telegram 更新都在 Vercel Function 的执行时长内完成；大量图片/ZIP 下载可能超时。Vercel 版本不提供 FFmpeg Ugoira 转码。需要完整动图转换或高负载批量下载时，使用下方 Docker/常驻服务器部署方式。

首次迁移不会自动读取旧服务器的 `data/` 文件；部署后请重新验证密码、设置管理员权限并按需配置 Pixiv Cookie 和收藏监控。

### 方式 A：Docker 推荐方式（最省心，已内置 FFmpeg）

1. 连接到你的 Linux 服务器（Ubuntu / Debian / CentOS）：
```bash
mkdir -p /opt/pixiv-bot && cd /opt/pixiv-bot
```

2. 将导出的源码文件上传或解压到该目录。

3. 编辑环境配置文件 `.env`：
```bash
nano .env
# 填入你的 TELEGRAM_BOT_TOKEN
```

4. 启动容器：
```bash
docker compose up -d --build
```

5. 查看实时日志确认是否启动：
```bash
docker compose logs -f
```
出现 `✅ 机器人启动成功，正在轮询监听消息...` 即表示部署成功！

---

### 方式 B：Node.js 原生运行（适合已有 Node 环境）

1. 安装 FFmpeg：
```bash
# Ubuntu / Debian:
sudo apt update && sudo apt install -y ffmpeg

# CentOS:
sudo dnf install -y epel-release
sudo dnf install -y ffmpeg
```

2. 安装 Node.js 20+ 并安装依赖：
```bash
npm install
```

3. 使用 PM2 守护进程运行：
```bash
npm install -g pm2
pm2 start bot.ts --name pixiv-bot --interpreter tsx
pm2 save
pm2 startup
```

---

## ❓ 常见问题 FAQ

- **Q1: 为什么普通机器人转发 Pixiv 图片会报 403 Forbidden？**  
  因为 Pixiv 的图片源站 `i.pximg.net` 设置了严格的防盗链规则。直接将图片 URL 交给 Telegram 服务器拉取时，Telegram 请求头中没有 `Referer`，就会被拦截。本项目通过在本地服务器流式下载或通过代理中继解决了此问题。

- **Q2: Ugoira 动图为什么需要 FFmpeg？**  
  Pixiv 的动图不是普通的 GIF，而是一个包含多张单独 JPG/PNG 的 ZIP 压缩包加上一份每帧延迟列表。本项目自动解压并使用 FFmpeg 的 concat 滤镜将所有帧严格按照画师设定的延迟毫秒精准拼装为 MP4，画质极高且体积极小。
