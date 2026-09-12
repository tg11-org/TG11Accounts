#!/usr/bin/env bash
set -euo pipefail
APP=/var/www/TG11Accounts
cd "$APP"
id tg11accounts >/dev/null 2>&1 || useradd --system --home "$APP" --shell /usr/sbin/nologin tg11accounts
mkdir -p "$APP/data"; chown -R tg11accounts:tg11accounts "$APP/data"; chmod 750 "$APP/data"
[ -f .env ] && { chown root:tg11accounts .env; chmod 640 .env; }
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip; .venv/bin/pip install -q -r requirements.txt
cp deploy/systemd/tg11-accounts.service /etc/systemd/system/tg11-accounts.service
systemctl daemon-reload; systemctl enable -q tg11-accounts; systemctl restart tg11-accounts; sleep 2
systemctl --no-pager status tg11-accounts | head -5
curl -fsS http://127.1.0.5:8000/healthz && echo
