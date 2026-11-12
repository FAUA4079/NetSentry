#!/usr/bin/env bash
# Reset ONLY NetSentry data. Never use docker volume prune or compose down -v.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -f compose.yaml || ! -f netsentry/storage.py ]]; then
  echo 'ERROR: Run from an existing NetSentry project (compose.yaml and netsentry/storage.py required).' >&2
  exit 1
fi
if [[ "${1:-}" != "--yes" ]]; then
  echo 'This PERMANENTLY deletes NetSentry alerts, packet statistics/metadata, policies,'
  echo 'response audit, incidents and incident events from this Compose project.'
  echo 'It does not delete source code, detection rules, images or unrelated Docker projects.'
  read -r -p 'Type RESET NETSENTRY to continue: ' consent
  [[ "$consent" == 'RESET NETSENTRY' ]] || { echo 'Cancelled; nothing changed.'; exit 0; }
fi

echo '[1/3] Stopping NetSentry containers (without deleting its volume)...'
docker compose down

echo '[2/3] Deleting ONLY the NetSentry SQLite files from its named volume...'
docker compose run --rm --no-deps -T dashboard python -c '
import os
from pathlib import Path
folder = Path("/data")
if not folder.is_dir():
    raise SystemExit("Missing /data mount: refusing reset")
for suffix in ("", "-wal", "-shm", "-journal"):
    p = folder / ("netsentry.db" + suffix)
    if p.is_symlink():
        raise SystemExit(f"Refusing symlink: {p}")
    if p.is_file():
        p.unlink()
        print(f"Deleted {p}")
print("NetSentry database reset. No other files were deleted.")
'

echo '[3/3] Restarting the project with a fresh target network namespace and database...'
docker compose up -d
printf '\nReset complete. Verify with:\n  sudo docker compose ps\n  curl -s http://127.0.0.1:5000/api/stats | python3 -m json.tool\n'
