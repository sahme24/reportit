#!/bin/bash
# Sets one optional API key in .env and restarts the stack.
#
#   bash ~/catphish/deploy/set-key.sh ANTHROPIC_API_KEY
#   bash ~/catphish/deploy/set-key.sh VT_API_KEY
#
# The value is typed into a prompt rather than passed as an argument, so it
# stays out of shell history and out of the process list where any other
# user on the box could read it.

set -e

KEY="$1"
case "$KEY" in
  ANTHROPIC_API_KEY|VT_API_KEY|ABUSEIPDB_API_KEY|URLHAUS_API_KEY) ;;
  *) echo "Usage: $0 <ANTHROPIC_API_KEY|VT_API_KEY|ABUSEIPDB_API_KEY|URLHAUS_API_KEY>"
     exit 1;;
esac

ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
[ -f "$ENV_FILE" ] || { echo "ERROR: no .env at $ENV_FILE"; exit 1; }

echo "Setting $KEY."
if [ "$KEY" = "ANTHROPIC_API_KEY" ]; then
  echo "Get one at https://platform.claude.com -> API keys."
  echo ""
  echo "Note: with this set, scanning becomes capped at 3 per user per"
  echo "rolling 24h, because every scan then calls the API and costs you"
  echo "money. Without it scanning is unlimited, just without the AI."
fi
echo ""
echo "The value will NOT appear as you type or paste -- that is deliberate."
echo "Paste it ONCE and press Enter. The character count is echoed back so"
echo "you can tell it arrived."

read -r -s -p "$KEY: " VALUE
echo ""
echo "  captured ${#VALUE} characters"

[ -n "$VALUE" ] || { echo "ERROR: empty value, nothing written."; exit 1; }

# Catch a double paste, which a hidden prompt actively invites: with no
# feedback it looks like nothing registered, so it gets pasted again.
if [ "$KEY" = "ANTHROPIC_API_KEY" ]; then
  case "$VALUE" in
    sk-ant-*) ;;
    *) echo "ERROR: an Anthropic key starts with 'sk-ant-'. Nothing written."; exit 1;;
  esac
  COPIES="$(printf '%s' "$VALUE" | grep -o 'sk-ant-' | wc -l | tr -d ' ')"
  if [ "$COPIES" -gt 1 ]; then
    echo "ERROR: 'sk-ant-' appears $COPIES times, so it was pasted $COPIES"
    echo "       times rather than once. Nothing written. A blank screen"
    echo "       while pasting is normal -- paste once and press Enter."
    exit 1
  fi
fi
case "$VALUE" in
  *[[:space:]]*) echo "ERROR: the value contains whitespace, which usually means"
                 echo "       extra text was copied. Nothing written."; exit 1;;
esac

cp "$ENV_FILE" "$ENV_FILE.bak"
esc() { printf '%s' "$1" | sed -e 's/[&|\]/\&/g'; }
if grep -q "^$KEY=" "$ENV_FILE"; then
  sed -i "s|^$KEY=.*|$KEY=$(esc "$VALUE")|" "$ENV_FILE"
else
  printf '%s=%s\n' "$KEY" "$VALUE" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE" "$ENV_FILE.bak"

WROTE="$(grep "^$KEY=" "$ENV_FILE" | cut -d= -f2-)"
[ -n "$WROTE" ] || { echo "ERROR: $KEY still empty; restored backup."
                     mv "$ENV_FILE.bak" "$ENV_FILE"; exit 1; }
echo "  $KEY set (${#WROTE} chars)"

echo ""
echo "==> Restarting"
cd "$(dirname "$0")"
docker compose --env-file ../.env up -d
echo ""
echo "==> Confirming the app sees it"
sleep 6
docker compose --env-file ../.env exec -T app python -c "
from threadline import ai
print('    ai.is_configured():', ai.is_configured())
" 2>/dev/null || echo "    (container still starting -- re-check in a few seconds)"
