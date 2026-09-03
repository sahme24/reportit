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

echo ""
echo "Now the client secret. It will NOT appear as you type or paste --"
echo "that is deliberate, so it never shows on screen. Paste it ONCE and"
echo "press Enter. The character count is echoed back so you can confirm"
echo "it arrived."
# -s keeps the secret off the screen. The cost is that a paste looks like
# nothing happened, which invites pasting again and again -- the checks
# below exist because exactly that produced a 304-character value made of
# nine concatenated secrets.
read -r -s -p "Client secret: " CLIENT_SECRET
echo ""
echo "  captured ${#CLIENT_SECRET} characters"

[ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] || { echo "ERROR: both values are required."; exit 1; }

case "$CLIENT_ID" in
  *.apps.googleusercontent.com) ;;
  *) echo "ERROR: that doesn't look like a client ID -- it should end in"
     echo "       .apps.googleusercontent.com. Nothing was written."; exit 1;;
esac

# One secret, pasted once. Google's are ~35 characters and start GOCSPX-.
COPIES="$(printf '%s' "$CLIENT_SECRET" | grep -o 'GOCSPX-' | wc -l | tr -d ' ')"
if [ "$COPIES" -gt 1 ]; then
  echo ""
  echo "ERROR: the secret contains 'GOCSPX-' $COPIES times, so it was pasted"
  echo "       $COPIES times rather than once. Nothing was written."
  echo "       Re-run and paste once -- the screen staying blank is normal."
  exit 1
fi
if [ "${#CLIENT_SECRET}" -gt 60 ]; then
  echo ""
  echo "ERROR: the secret is ${#CLIENT_SECRET} characters; Google's are around 35."
  echo "       That usually means it was pasted more than once, or the whole"
  echo "       JSON was pasted instead of just the secret. Nothing was written."
  exit 1
fi

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
