#!/usr/bin/env bash
# Back up a forge into one bundle: the database through sqlite's backup API
# (a plain copy of a live database can miss what is still in the WAL), the
# receipt signing key, and the repositories. The copy is integrity-checked
# before it is kept. Older bundles beyond AMBOLT_KEEP are removed.
#
#   AMBOLT_DB=/srv/ambolt/ambolt.db AMBOLT_REPOS=/srv/ambolt/repos scripts/backup.sh
#
# AMBOLT_KEY defaults to signing.key beside the database, AMBOLT_BACKUPS to a
# backups/ directory beside it, AMBOLT_KEEP to 30. To restore, extract the
# bundle and point `ambolt serve` (or `ambolt admin fsck`) at the copies.
set -euo pipefail
umask 077

DB=${AMBOLT_DB:-ambolt.db}
REPOS=${AMBOLT_REPOS:-repos}
KEY=${AMBOLT_KEY:-$(dirname "$DB")/signing.key}
OUT=${AMBOLT_BACKUPS:-$(dirname "$DB")/backups}
KEEP=${AMBOLT_KEEP:-30}
[ -f "$DB" ] || { echo "no database at $DB"; exit 1; }
[ -d "$REPOS" ] || { echo "no repositories at $REPOS"; exit 1; }

mkdir -p "$OUT"
stamp=$(date -u +%Y%m%d-%H%M%S)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 - "$DB" "$work/ambolt.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
check = sqlite3.connect(sys.argv[2]).execute("PRAGMA integrity_check").fetchone()[0]
print("integrity:", check)
sys.exit(0 if check == "ok" else 1)
PY
if [ -f "$KEY" ]; then cp "$KEY" "$work/signing.key"; else echo "no signing key at $KEY; the bundle has none"; fi
tar -C "$(dirname "$REPOS")" -cf "$work/repos.tar" "$(basename "$REPOS")"
bundle="$OUT/ambolt-$stamp.tar.gz"
tar -C "$work" -czf "$bundle" ambolt.db repos.tar $( [ -f "$work/signing.key" ] && echo signing.key )
ls -1t "$OUT"/ambolt-*.tar.gz | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup: $bundle ($(wc -c <"$bundle" | tr -d ' ') bytes), $(ls -1 "$OUT"/ambolt-*.tar.gz | wc -l | tr -d ' ') kept"
