#!/usr/bin/env bash
# ==============================================================================
# Pixiv Telegram Bot 一键安装与部署脚本
# 适用系统: Ubuntu 20.04+, Debian 11+, CentOS 8+
# ==============================================================================
set -e

echo "🚀 [1/5] 检查系统环境与 Docker 支持..."
if ! command -v docker &> /dev/null; then
    echo "📦 未检测到 Docker，正在自动安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

if ! docker compose version &> /dev/null; then
    echo "📦 正在安装 Docker Compose 插件..."
    apt-get update && apt-get install -y docker-compose-plugin || yum install -y docker-compose-plugin
fi

echo "📂 [2/5] 创建部署工作目录: /opt/pixiv-bot..."
mkdir -p /opt/pixiv-bot
cd /opt/pixiv-bot

echo "📝 [3/5] 写入环境配置文件..."
cat << 'EOF' > .env
TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
UGOIRA_OUTPUT_FORMAT=mp4
SEND_MODE=document_and_photo
EOF

echo "🐳 [4/5] 启动 Docker 容器..."
docker compose up -d --build

echo "🎉 [5/5] 部署完成！"
echo "=========================================================="
echo "查看运行日志命令:  docker compose logs -f"
echo "重启机器人命令:    docker compose restart"
echo "停止机器人命令:    docker compose down"
echo "=========================================================="
