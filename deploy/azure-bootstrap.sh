#!/bin/bash
# Runs ON the Azure VM, once, after azure-provision.sh created it.
#
#   scp deploy/azure-bootstrap.sh azureuser@<fqdn>:~
#   ssh azureuser@<fqdn> 'bash azure-bootstrap.sh'
#
# Installs Docker, adds swap, opens the instance firewall, and clones the
# repo. It deliberately stops before starting the app, because that needs
# a .env you have to write by hand -- the secrets should not pass through
# a script, a shell history, or this file.

set -e

REPO="${REPO:-https://github.com/sahme24/reportit.git}"
DIR="${DIR:-$HOME/catphish}"

echo "==> System packages"
sudo apt-get update -qq
sudo apt-get install -y -qq ca-certificates curl git

echo "==> Swap"
# The B1s has 1 GB of RAM. Headless Chromium wants roughly that on its own,
# so without swap the first detonation OOM-kills either the browser or the
# app. Chromium's footprint is mostly cold pages, so swap costs speed rather
# than correctness -- and 4 GB of disk is free where more RAM is not.
if [ ! -f /swapfile ]; then
  sudo fallocate -l 4G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile >/dev/null
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
  # Default swappiness of 60 pages things out too eagerly for a box this
  # small; 10 keeps the app resident and uses swap as the overflow it is.
  echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swap.conf >/dev/null
  sudo sysctl -q -w vm.swappiness=10
  echo "    4G swap added"
else
  echo "    already present"
fi

echo "==> Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh >/dev/null
  sudo usermod -aG docker "$USER"
  echo "    installed"
else
  echo "    already installed"
fi

echo "==> Instance firewall"
# Azure's network security group is one layer; ufw on the instance is
# another. Both must allow 80/443 or Let's Encrypt cannot validate the
# domain, and the failure looks like a certificate problem rather than a
# firewall one.
if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow 22/tcp   >/dev/null 2>&1 || true
  sudo ufw allow 80/tcp   >/dev/null 2>&1 || true
  sudo ufw allow 443/tcp  >/dev/null 2>&1 || true
  echo "    22, 80, 443 allowed"
fi

echo "==> Repository"
if [ ! -d "$DIR" ]; then
  git clone -q "$REPO" "$DIR"
  echo "    cloned to $DIR"
else
  git -C "$DIR" pull -q
  echo "    updated"
fi

FQDN="$(hostname -f 2>/dev/null || echo "<your-fqdn>")"

cat <<EOF

============================================================
  Ready. Two things left, both needing your secrets.
============================================================

1. Write the environment file:

     nano $DIR/.env

   It needs, at minimum:

     CATPHISH_DOMAIN=$FQDN
     OAUTH_REDIRECT_URL=https://$FQDN/auth/google/callback
     GOOGLE_CLIENT_ID=...
     GOOGLE_CLIENT_SECRET=...

   Optional: ANTHROPIC_API_KEY, VT_API_KEY, ABUSEIPDB_API_KEY,
   URLHAUS_API_KEY. See .env.example in the repo.

   OAUTH_REDIRECT_URL is both the OAuth callback and the source of
   _CANONICAL_HOST in app.py. Get it wrong and every request redirects
   somewhere unexpected -- check it first if the site misbehaves.

   Detonation is ON here (unlike the free hosts), so do NOT set
   REPORTIT_SANDBOX=off unless you want it disabled.

2. Start it:

     cd $DIR/deploy
     docker compose --env-file ../.env up -d --build

   The first build takes 10-15 minutes: it downloads Chromium. Caddy then
   gets a certificate from Let's Encrypt automatically.

If docker says "permission denied", log out and back in once -- the group
membership added above only applies to new sessions.

     docker compose logs -f        # watch it come up
EOF
