#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f /swapfile ]]; then
  fallocate -l 1G /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl git gnupg python3-venv sqlite3 rsync

if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy
fi

if ! id betglobal >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/betglobal --create-home --shell /usr/sbin/nologin betglobal
fi

install -d -o betglobal -g betglobal -m 0750 /var/lib/betglobal/uploads/dispute_evidence
install -d -o betglobal -g betglobal -m 0700 /var/lib/betglobal/backups
install -d -o root -g betglobal -m 0750 /etc/betglobal
install -d -o betglobal -g betglobal -m 0755 /opt/betglobal

if [[ ! -f /etc/betglobal/betglobal.env ]]; then
  install -o root -g betglobal -m 0640 "$repo_root/deploy/betglobal.env.example" /etc/betglobal/betglobal.env
  echo "Created /etc/betglobal/betglobal.env; populate secrets before starting the app." >&2
fi

python3 -m venv /opt/betglobal/venv
/opt/betglobal/venv/bin/pip install --upgrade pip
/opt/betglobal/venv/bin/pip install -r "$repo_root/requirements.txt"
chown -R betglobal:betglobal /opt/betglobal/venv

install -o root -g root -m 0644 "$repo_root/deploy/systemd/betglobal.service" /etc/systemd/system/betglobal.service
install -o root -g root -m 0644 "$repo_root/deploy/systemd/betglobal-backup.service" /etc/systemd/system/betglobal-backup.service
install -o root -g root -m 0644 "$repo_root/deploy/systemd/betglobal-backup.timer" /etc/systemd/system/betglobal-backup.timer
install -o root -g root -m 0644 "$repo_root/deploy/caddy/Caddyfile" /etc/caddy/Caddyfile

install -d -m 0755 /etc/systemd/system/caddy.service.d
printf '%s\n' '[Service]' 'EnvironmentFile=/etc/betglobal/caddy.env' > /etc/systemd/system/caddy.service.d/betglobal.conf

if [[ ! -f /etc/betglobal/caddy.env ]]; then
  printf '%s\n' \
    'BETGLOBAL_HOST=replace-with-staging-hostname' \
    'BETGLOBAL_PUBLIC_HOST=betgloballive.com' \
    > /etc/betglobal/caddy.env
  chmod 0640 /etc/betglobal/caddy.env
  chown root:caddy /etc/betglobal/caddy.env
fi

systemctl daemon-reload
systemctl enable betglobal.service betglobal-backup.timer caddy.service
echo "Server prerequisites installed. Configure env files, install a release at /opt/betglobal/current, then start services."
