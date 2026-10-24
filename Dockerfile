# Dockerfile for Pixiv Telegram Bot (Node.js 20 + FFmpeg)
FROM node:20-alpine

# 安装 FFmpeg (Ugoira 动图转换核心依赖)
RUN apk add --no-cache ffmpeg python3 make g++ curl

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

# 编译 TypeScript 或直接使用 tsx 运行
RUN npm run build || true

ENV NODE_ENV=production
CMD ["npm", "start"]
