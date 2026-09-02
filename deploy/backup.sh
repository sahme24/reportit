#!/bin/bash
# Snapshots the CatPhish database off the Docker volume.
#
#   bash deploy/backup.sh              -> ./backups/threadline-YYYYMMDD-HHMM.db
#   bash deploy/backup.sh /mnt/disk    -> writes there instead
#
# On Cloud Run the database lived in a Cloud Storage bucket and Google kept
# it durable. On your own VM nothing does that for you: the Docker volume
# survives reboots and rebuilds, but not `docker compose down -v`, not a
# disk failure, and not the instance being reclaimed. Run this on a cron.
#
# Uses SQLite's own .backup rather than copying the file, because a plain cp
# of a live database can capture a half-written transaction and produce a
# snapshot that won't open.

set -e

DEST="${1:-$(dirname "$0")/../backups}"
STAMP="$(date +%Y%m%d-%H%M)"
OUT="$DEST/threadline-$STAMP.db"

mkdir -p "$DEST"

cd "$(dirname "$0")"

if ! docker compose ps --status running --services 2>/dev/null | grep -q '^app$'; then
  echo "ERROR: the app container isn't running, so there's nothing to back up."
  echo "       Start it first:  docker compose --env-file ../.env up -d"
  exit 1
fi

echo "==> Snapshotting the database"
# .backup is safe against a live writer; cp is not.
docker compose exec -T app python -c "
import sqlite3
source = sqlite3.connect('/data/threadline.db')
target = sqlite3.connect('/tmp/backup.db')
source.backup(target)
target.close()
source.close()
"
docker compose cp app:/tmp/backup.db "$OUT"
docker compose exec -T app rm -f /tmp/backup.db

echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1))"

# Keep the last 14 and drop the rest, so a daily cron can't quietly fill
# the boot volume over a few months.
COUNT="$(ls -1 "$DEST"/threadline-*.db 2>/dev/null | wc -l)"
if [ "$COUNT" -gt 14 ]; then
  ls -1t "$DEST"/threadline-*.db | tail -n +15 | while read -r old; do
    rm -f "$old"
    echo "    pruned $(basename "$old")"
  done
fi

echo ""
echo "    A backup on the same VM only protects against a bad deploy, not"
echo "    against losing the VM. Copy these somewhere else periodically."
