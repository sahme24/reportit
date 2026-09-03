#!/bin/bash
# Prompts for the Google OAuth client ID and secret, writes them into
# .env, and restarts the stack.
#
#   bash ~/catphish/deploy/set-google-oauth.sh
#
# The values are typed straight into this script's prompts. They are never
# passed as arguments, so they don't land in your shell history or in the
# process list where other users on the box could read them.

set -e

ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
[ -f "$ENV_FILE" ] || { echo "ERROR: no .env at $ENV_FILE"; exit 1; }

# The callback that must be registered on the OAuth client, read back from
# the file so it can't drift from what the app actually sends.
CALLBACK="$(grep '^OAUTH_REDIRECT_URL=' "$ENV_FILE" | cut -d= -f2-)"
echo "Register this exact URI on the OAuth client first:"
echo "    $CALLBACK"
echo ""

read -r -p "Client ID (ends .apps.googleusercontent.com): " CLIENT_ID
# -s: the secret isn't echoed to the terminal as it's typed.
read -r -s -p "Client secret (hidden): " CLIENT_SECRET
echo ""

[ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] || { echo "ERROR: both values are required."; exit 1; }
case "$CLIENT_ID" in
  *.apps.googleusercontent.com) ;;
  *) echo "ERROR: that doesn't look like a client ID -- it should end in"
     echo "       .apps.googleusercontent.com. Nothing was written."; exit 1;;
esac

# A backup, because a bad sed against the only copy of this file means
# retyping every key in it.
cp "$ENV_FILE" "$ENV_FILE.bak"

# Escaped for sed's replacement side: & and | are special there, and a
# secret containing either would otherwise be silently mangled.
esc() { printf '%s' "$1" | sed -e 's/[&|\]/\&/g'; }
sed -i "s|^GOOGLE_CLIENT_ID=.*|GOOGLE_CLIENT_ID=$(esc "$CLIENT_ID")|" "$ENV_FILE"
sed -i "s|^GOOGLE_CLIENT_SECRET=.*|GOOGLE_CLIENT_SECRET=$(esc "$CLIENT_SECRET")|" "$ENV_FILE"
chmod 600 "$ENV_FILE" "$ENV_FILE.bak"

# Confirm both lines are non-empty without printing what they hold.
for k in GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET; do
  v="$(grep "^$k=" "$ENV_FILE" | cut -d= -f2-)"
  [ -n "$v" ] || { echo "ERROR: $k is still empty. Restored from backup."
                   mv "$ENV_FILE.bak" "$ENV_FILE"; exit 1; }
  echo "  $k set (${#v} chars)"
done

echo ""
echo "==> Restarting"
cd "$(dirname "$0")"
docker compose --env-file ../.env up -d

echo ""
echo "==> Checking"
sleep 5
if curl -fsS --max-time 20 "$(dirname "$CALLBACK" | sed 's|/auth/google$||')/healthz" >/dev/null 2>&1; then
  echo "    app is up. Open the site and try Login with Google."
else
  echo "    app didn't answer /healthz yet -- give it a few seconds, then:"
  echo "    docker compose --env-file ../.env logs app --tail 30"
fi
