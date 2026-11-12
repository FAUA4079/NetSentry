#!/usr/bin/env bash
# Live 25-rule trigger coverage on NetSentry's isolated Docker bridge.
# Never changes analyst observe/block/release policies.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
COMPOSE=(docker compose)

usage() {
  cat <<'HELP'
Usage: sudo bash scripts/test_all_rules.sh [--quick]
  (default) Run 25 probes, then retry any missing rules after 35s cooldown.
  --quick   Run once; do not retry (useful for rapid diagnosis).

IMPORTANT: A previously blocked test source cannot complete HTTP probes.
To restore testing, review/release the blocked source through NetSentry's
IP Analysis page; this script will NEVER change an analyst policy.
HELP
}
QUICK=0
case "${1:-}" in
  '') ;;
  --quick) QUICK=1 ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 64 ;;
esac

for service in sensor target dashboard enforcer; do
  id=$("${COMPOSE[@]}" ps -q "$service")
  if [[ -z "$id" || "$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)" != true ]]; then
    echo "ERROR: '$service' is not running. Run: sudo docker compose up -d --build" >&2
    exit 1
  fi
done
[[ -f tests/live_rule_probe.py ]] || { echo 'ERROR: Missing tests/live_rule_probe.py' >&2; exit 1; }
image=$("${COMPOSE[@]}" images -q sensor | head -1)
[[ -n "$image" ]] || { echo 'ERROR: Sensor image unavailable' >&2; exit 1; }

expected=(PORT_SCAN TRAFFIC_SPIKE RESTRICTED_PORT SYN_BURST ICMP_ECHO_FLOOD UDP_PORT_SCAN UDP_BURST TCP_RST_BURST TCP_FIN_SCAN TCP_NULL_SCAN TCP_XMAS_SCAN TCP_ACK_PROBE IP_FRAGMENT ICMP_LARGE_ECHO ICMP_UNREACH_BURST DNS_QUERY_BURST DNS_LONG_QUERY DNS_HIGH_ENTROPY_LABEL DNS_TXT_BURST DNS_UNIQUE_NAME_BURST DNS_NXDOMAIN_BURST HTTP_SENSITIVE_PATH HTTP_UNCOMMON_METHOD HTTP_LONG_URI HTTP_SCANNER_USER_AGENT)
source_ips=()
probe_log=$(mktemp)
trap 'rm -f "$probe_log"' EXIT

probe() {
  docker run --rm --network netsentry_lab --cap-drop ALL --cap-add NET_RAW \
    -v "$PWD/tests/live_rule_probe.py:/work/probe.py:ro" \
    --entrypoint python "$image" /work/probe.py "$@"
}

show_policy_diagnostics() {
  echo '--- Current lab policies (read only) ---' >&2
  "${COMPOSE[@]}" exec -T dashboard python -c '
from netsentry.response import policies
for p in policies():
 if p["mode"] in ("observe", "blocked"):
  print("%s: %s (%s)" % (p["ip"], p["mode"], p["apply_state"]))
' >&2 || true
  echo '--- NETSENTRY firewall chain (read only) ---' >&2
  "${COMPOSE[@]}" exec -T enforcer iptables -L NETSENTRY -n -v -x >&2 || true
  echo 'Action: open http://127.0.0.1:5000; Analyze the flagged IP; if safe and authorized, Release it.' >&2
  echo 'Do NOT delete the whole Docker volume, flush iptables, or automatically unblock analyst policies.' >&2
}

baseline=$("${COMPOSE[@]}" exec -T dashboard python -c '
from netsentry.storage import connect
with connect() as db:
 print(db.execute("SELECT COALESCE(MAX(id),0) FROM alerts").fetchone()[0])
' | tail -1 | tr -d '\r')
[[ "$baseline" =~ ^[0-9]+$ ]] || { echo 'ERROR: Failed to read alert baseline' >&2; exit 1; }

run_probe() {
  local rc=0 source
  probe "$@" >"$probe_log" 2>&1 || rc=$?
  cat "$probe_log"
  source=$(sed -n 's/^\[+] Probe source: //p' "$probe_log" | tail -1 | tr -d '\r')
  if [[ "$source" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    source_ips+=("$source")
  fi
  if (( rc != 0 )); then
    echo "ERROR: Probe exited with code $rc." >&2
    if grep -q '^\[FATAL\]' "$probe_log"; then show_policy_diagnostics; fi
    return 1
  fi
  if grep -q '^\[!\]' "$probe_log"; then
    echo 'ERROR: Some probes raised exceptions; test cannot be counted as complete.' >&2
    return 1
  fi
}

get_counts() {
  local joined
  joined=$(IFS=,; echo "${source_ips[*]}")
  "${COMPOSE[@]}" exec -T \
    -e NETSENTRY_TEST_BASELINE="$baseline" -e NETSENTRY_TEST_SOURCES="$joined" \
    dashboard python -c '
import os
from netsentry.storage import connect
ips=[x for x in os.environ["NETSENTRY_TEST_SOURCES"].split(",") if x]
if not ips: raise SystemExit("No probe source IPs")
marks=",".join("?" for _ in ips)
with connect() as db:
 rows=db.execute("SELECT rule_id,COUNT(*) AS n FROM alerts WHERE id>? AND source_ip IN ("+marks+") GROUP BY rule_id",(int(os.environ["NETSENTRY_TEST_BASELINE"]),*ips)).fetchall()
for row in rows: print(row["rule_id"],row["n"])
'
}

report_counts() {
  declare -gA counts=()
  while read -r rule amount; do
    [[ -n "${rule:-}" ]] && counts["$rule"]="$amount"
  done < <(get_counts)
  missing=()
  for rule in "${expected[@]}"; do
    [[ ${counts[$rule]:-0} -gt 0 ]] || missing+=("$rule")
  done
}

echo "[1/4] Starting alert ID: $baseline"
echo '[2/4] Running preflight and 25 lab-only probes...'
run_probe --all
sleep 3
report_counts
echo "Round 1: $((25-${#missing[@]}))/25 distinct rules generated new alerts."
if (( ${#missing[@]} > 0 && QUICK == 0 )); then
  echo "[3/4] Retrying only ${#missing[@]} missing rules after cooldown: ${missing[*]}"
  echo 'The 35-second cooldown is intentional; do not interrupt to get a final report.'
  for elapsed in 5 10 15 20 25 30 35; do
    sleep 5
    printf '  Cooldown: %d/35 seconds\n' "$elapsed"
  done
  retry=("${missing[@]}")
  for rule in "${retry[@]}"; do
    echo "Retrying $rule..."
    run_probe --rule "$rule"
  done
  sleep 3
  report_counts
fi

echo '[4/4] Final rule trigger report (new alerts in this run):'
passed=0
for rule in "${expected[@]}"; do
  if [[ ${counts[$rule]:-0} -gt 0 ]]; then
    printf 'PASS %-28s alerts=%s\n' "$rule" "${counts[$rule]}"
    ((passed+=1))
  else
    printf 'MISS %-28s alerts=0\n' "$rule"
  fi
done
printf '\nTriggered: %d/25 (trigger coverage, NOT detection accuracy).\n' "$passed"
if (( passed != 25 )); then
  echo 'Review sensor logs, alert cooldown, packet visibility and rule thresholds for the remaining misses.' >&2
  exit 2
fi
