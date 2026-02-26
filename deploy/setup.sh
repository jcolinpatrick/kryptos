#!/usr/bin/env bash
set -euo pipefail

# kryptosbot.com — one-shot install & deploy
# Idempotent: safe to re-run.

REPO_DIR="/home/cpatrick/kryptos"
VENV_DIR="$REPO_DIR/venv"
NGINX_CONF="$REPO_DIR/deploy/kryptosbot.nginx"
SYSTEMD_UNIT="$REPO_DIR/deploy/kryptosbot-api.service"

echo "=== 1/7  Installing system packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq nginx certbot python3-certbot-nginx

echo "=== 2/7  Installing Python dependencies in venv ==="
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet jinja2 fastapi uvicorn anthropic

echo "=== 3/7  Building static site ==="
cd "$REPO_DIR"
PYTHONPATH=src "$VENV_DIR/bin/python3" site_builder/build.py

echo "=== 4/7  Installing nginx config ==="
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/kryptosbot.conf
# Remove default site if it exists (avoids port-80 conflict)
sudo rm -f /etc/nginx/sites-enabled/default
echo "Testing nginx config..."
sudo nginx -t

echo "=== 5/7  Reloading nginx ==="
sudo systemctl enable nginx
sudo systemctl reload nginx

echo "=== 6/7  Installing systemd unit ==="
sudo ln -sf "$SYSTEMD_UNIT" /etc/systemd/system/kryptosbot-api.service
sudo systemctl daemon-reload
sudo systemctl enable kryptosbot-api
sudo systemctl restart kryptosbot-api

echo "=== 7/7  Done ==="
echo ""
echo "Remaining manual steps:"
echo ""
echo "  1. Create /home/cpatrick/kryptos/.env with:"
echo "       ANTHROPIC_API_KEY=sk-ant-..."
echo ""
echo "  2. Obtain TLS certificate:"
echo "       sudo certbot --nginx -d kryptosbot.com -d www.kryptosbot.com"
echo ""
echo "  3. Verify:"
echo "       sudo systemctl status kryptosbot-api"
echo "       curl -s http://localhost:8321/api/health"
echo "       curl -s http://kryptosbot.com/"
