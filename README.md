# NetSentry Cyber Range

**Educational, Docker-isolated network monitoring, intrusion detection, human-reviewed containment, and IP investigation.**

NetSentry provides a small cyber range with a web target, an attacker toolbox, a Scapy packet sensor, a Flask dashboard and an isolated target-namespace firewall enforcer. It implements **25 configurable heuristic detection rules**, saves alerts and sampled packet metadata in SQLite, and lets a human analyst **Observe** (rate-limit), **Block** or **Release** a flagged lab source IP. Its analysis page includes alert evidence, firewall DROP counters, explainable IP risk scoring, traffic summaries and analyst-managed incidents.

> **Important:** This is a university/classroom prototype, **not** a production IDS or IPS. Alerts are suspicious indicators, not proof of malicious intent. Its dashboard has **no user authentication**, so **do not expose port 5000 beyond localhost** or deploy the test target on a public network. It does not automatically block IPs.

## Architecture

```text
Your Linux computer (Docker Engine + Compose)
  ├── netsentry_lab — isolated Docker bridge (internal: true)
  │     ├── attacker — nicolaka/netshoot (Nmap/curl)
  │     └── target — nginx:1.27-alpine, HTTP/80, no public port
  │           ├── sensor — shares target network namespace; Scapy
  │           └── enforcer — shares target network namespace; NETSENTRY iptables chain
  └── management bridge
        └── dashboard — Flask, bound only to 127.0.0.1:5000

Shared Docker named volume: netsentry_data (SQLite alerts, packets, incidents, policies)
```

The sensor shares the target's network namespace because ordinary Docker bridge containers do **not** automatically observe one another's traffic. It may see incoming packets **even when the firewall subsequently drops them**. The firewall DROP counter is distinct from the Scapy packet count.

## 1. Requirements

- Kali Linux, Ubuntu or another Linux host with Docker Engine and Docker Compose v2.
- Internet for the **initial** Docker image pulls and Python dependency installation.
- Sufficient disk space for the Docker images (the `netshoot` image is comparatively large).
- `sudo` access for Docker commands, unless your user already has permission. **Docker group membership gives root-equivalent access**; understand the risk before using it.
- Ports: `127.0.0.1:5000` must be free.

Use **only** the network and containers supplied by this project for its test traffic.

### Check Docker

```bash
docker --version
docker compose version
sudo systemctl is-active docker
sudo docker info
```

If `DOCKER_HOST` points to `unix:///run/user/1000/podman/podman.sock` while you intend to use Docker Engine:

```bash
unset DOCKER_HOST DOCKER_CONTEXT
sudo docker info
```

If necessary, review `~/.zshrc` / `~/.bashrc` for a stale `DOCKER_HOST` override. You should **not** reinstall Docker if the daemon is already active. Docker's usual rootful Unix socket is `/var/run/docker.sock`.

## 2. Download and start a fresh installation

1. Download this repository from GitHub using **Code → Download ZIP**, or clone it.
2. Extract the ZIP and **enter the folder that contains `compose.yaml`**.
3. Run:

```bash
cd ~/Downloads/NetSentry-Cyber-Range   # adjust to your actual extracted folder
sudo docker compose config
sudo docker compose up -d --build
sudo docker compose ps -a
```

Expected running services: **attacker, target, sensor, dashboard, enforcer**. The first build downloads external images and installs dependencies; subsequent builds can reuse Docker cache.

Open **http://127.0.0.1:5000** in a browser **on the Docker host itself**.

```bash
curl -fsS http://127.0.0.1:5000/health
sudo docker compose logs --tail=40 sensor
sudo docker compose logs --tail=40 enforcer
```

The initial dashboard may have **zero alerts**. This is normal: fresh repositories intentionally contain no runtime database.

### Where is data stored?

SQLite lives in a **Docker named volume**, not in your GitHub source tree. The volume is created on first start. The `database/` and `captures/` directories in the repository are placeholders. Your local database, captures, `.env` and Python caches are excluded by `.gitignore` and `.dockerignore`.

## 3. First network test

```bash
sudo docker compose exec attacker curl -I http://target
sudo docker compose exec attacker nmap -sT -Pn -p 1-100 target
```

Expected: HTTP `200 OK`, Nmap identifies HTTP port `80/tcp` open, and NetSentry may generate `PORT_SCAN`, `TRAFFIC_SPIKE`, and `RESTRICTED_PORT` alerts. The precise alerts depend on traffic volume and cooldown. Check:

```bash
curl -sS http://127.0.0.1:5000/api/stats | python3 -m json.tool
sudo docker compose logs --tail=80 sensor
```

A single scan can trigger **multiple** heuristic rules. An alert does not mean the scan succeeded in gaining access.

## 4. All 25 detection rules

| # | Rule | # | Rule |
|---:|---|---:|---|
| 1 | `PORT_SCAN` | 14 | `ICMP_LARGE_ECHO` |
| 2 | `TRAFFIC_SPIKE` | 15 | `ICMP_UNREACH_BURST` |
| 3 | `RESTRICTED_PORT` | 16 | `DNS_QUERY_BURST` |
| 4 | `SYN_BURST` | 17 | `DNS_LONG_QUERY` |
| 5 | `ICMP_ECHO_FLOOD` | 18 | `DNS_HIGH_ENTROPY_LABEL` |
| 6 | `UDP_PORT_SCAN` | 19 | `DNS_TXT_BURST` |
| 7 | `UDP_BURST` | 20 | `DNS_UNIQUE_NAME_BURST` |
| 8 | `TCP_RST_BURST` | 21 | `DNS_NXDOMAIN_BURST` |
| 9 | `TCP_FIN_SCAN` | 22 | `HTTP_SENSITIVE_PATH` |
| 10 | `TCP_NULL_SCAN` | 23 | `HTTP_UNCOMMON_METHOD` |
| 11 | `TCP_XMAS_SCAN` | 24 | `HTTP_LONG_URI` |
| 12 | `TCP_ACK_PROBE` | 25 | `HTTP_SCANNER_USER_AGENT` |
| 13 | `IP_FRAGMENT` | | |

Edit `config/rules.json` to enable/disable rule IDs or change thresholds. Validate and restart the sensor:

```bash
sudo docker compose exec sensor python -m netsentry.config
sudo docker compose restart sensor
```

Rules are threshold-based heuristics. Some DNS probes use synthetic packets rather than a real DNS server; HTTP application rules inspect plain HTTP, **not encrypted HTTPS**.

## 5. Reliable 25-rule test runner

**Before testing:** Review the active containment policies in the dashboard. If the temporary test container's source IP was previously **Blocked** or **Observed**, it may not reach the target. **Only an authorized analyst should Release that IP from the Analysis page**. The test runner will not silently change firewall policies.

```bash
sudo bash scripts/test_all_rules.sh
```

The runner:

1. Confirms the necessary services are running.
2. Records the starting alert ID, ensuring old alerts cannot count as new test detections.
3. Creates a temporary **lab-only** traffic generator using the already-built sensor image and `NET_RAW` capability.
4. Performs an HTTP preflight; if it times out, it **stops** and prints current policies and firewall counters.
5. Runs all 25 probes and reports distinct new rule alerts from the probe IP.
6. If necessary, shows a **35-second cooldown countdown**, then retries *only* missing rules.
7. Reports `PASS` / `MISS` for each rule and a final triggered count.

**Do not interrupt the 35-second cooldown** if you want a final report. For a quick one-pass test:

```bash
sudo bash scripts/test_all_rules.sh --quick
```

An example of **successful formatting, not a promise that every run passes**:

```text
Round 1: 23/25 distinct rules generated new alerts.
[3/4] Retrying only 2 missing rules after cooldown...
  Cooldown: 5/35 seconds
  ...
PASS PORT_SCAN                    alerts=1
...
Triggered: 25/25 (trigger coverage, NOT detection accuracy).
```

If you get `Source 172.x.x.x cannot communicate with target: timed out`:

```bash
sudo docker compose exec enforcer iptables -L NETSENTRY -n -v -x
sudo docker compose logs --tail=80 enforcer
```

In the web dashboard, find the **exact probe source IP** shown in the test output → **Analyze** → inspect policy status → **Release** it if appropriate. Your *attacker* IP and temporary *probe* IP are normally different. **Do not use `iptables -F` or delete the database to bypass a human block.** A successful block test intentionally causes HTTP probes to time out.

For one rule and manual investigation, you can use the included read-only probe file with the existing sensor image:

```bash
sudo docker run --rm --network netsentry_lab --cap-drop ALL --cap-add NET_RAW \
  -v "$PWD/tests/live_rule_probe.py:/work/probe.py:ro" \
  --entrypoint python "$(sudo docker compose images -q sensor)" \
  /work/probe.py --rule HTTP_UNCOMMON_METHOD
```

Then review sensor logs. The rule tester checks **trigger coverage**, **not** detection accuracy, precision, recall, or false-positive rate. Measuring those needs a separate labelled benign/malicious benchmark.

## 6. Investigate suspicious IPs and human response

1. Open the dashboard → **Suspicious IPs**.
2. Click **Analyze** (opens a new browser tab).
3. Review risk score with its factor breakdown, recent alerts, packet metadata, protocol distribution, destination ports, incident notes and prior analyst actions.
4. Choose **Observe** (rate limit), **Block** (DROP lab-target incoming IPv4 traffic), or **Release**, with a human explanation.
5. Inspect the resulting `applied`/`error` status rather than assuming success.

The observation page includes **Dropped Packets** and **Dropped Bytes** from the `NETSENTRY` iptables chain. These are live *current-rule counters*, not an immutable all-time history. Rebuilding policies or recreating the target namespace can reset them. Packet metadata retention is limited; a date filter cannot recover already deleted observations.

Command-line cross-check:

```bash
sudo docker compose exec attacker hostname -i
sudo docker compose exec enforcer iptables -L NETSENTRY -n -v -x
sudo docker compose exec attacker curl --connect-timeout 3 --max-time 5 -I http://target
```

**If you blocked `172.20.0.4`, a test from `172.20.0.2` might still succeed because those are different sources.** The probe IP is temporary and can be reused by Docker after the container exits. Never interpret *observed packets* as *accepted communication*.

## 7. Incident management and risk scoring

On an IP Analysis page, create an incident case, assign an analyst, add investigation notes, and change its status `Open` → `Investigating` → `Resolved`. The system keeps audit events. **Resolving a case does not automatically unblock the IP**; that is a separate analyst decision.

Risk score is a transparent **0–100 heuristic** based on recent alert severities, distinct rules and activity frequency. It is neither an ML model nor a calibrated probability of compromise.

## 8. Troubleshooting and root causes

| Symptom | Likely cause | Check / fix |
|---|---|---|
| `Cannot connect ... podman.sock` | `DOCKER_HOST` points to Podman while Docker Engine is running | `echo "$DOCKER_HOST"`; `unset DOCKER_HOST DOCKER_CONTEXT`; `sudo docker info` |
| `service "attacker" is not running` | Images still downloading or `compose up` failed | `sudo docker compose up -d --build`; `sudo docker compose ps -a`; inspect logs |
| Image pull stops near 100% | Registry/CDN, network, transfer or extraction issue | Retry `sudo docker pull nicolaka/netshoot:latest`, check disk/network; don't delete unrelated CTF images |
| Port `5000` already allocated | Another service or NetSentry copy is listening | `sudo ss -ltnp | grep ':5000'`; stop conflicting process/project; keep dashboard localhost-only |
| Investigation API returns 404 | Old Flask route-placement bug or outdated image | This release places all routes **before** `app.run()`; `sudo docker compose up -d --build --no-deps dashboard`; `curl -i http://127.0.0.1:5000/api/investigate/172.19.0.3` |
| Dashboard says `0 filtered alerts` despite stored alerts | Time filter/cached JS issue | Choose **All history**, **All severities**, Apply, hard refresh `Ctrl+Shift+R`, inspect `/api/stats` |
| `ps: executable file not found` | `python:3.12-slim` has no `ps` utility | Not an app failure; use `docker compose ps` and logs |
| Probe HTTP tests time out | Test source IP is blocked or rate limited | Check probe IP and `NETSENTRY` DROP chain; review/release only if authorized |
| 22/25 or 23/25 triggered | Cooldown, threshold, timing or packet capture losses | Run default tester to complete its retry, then inspect `sensor` logs; do not claim accuracy from trigger coverage |
| After block, packets still appear | Scapy captures packets before firewall drop | Compare dashboard observed packets to `iptables` DROP counters and attempt an HTTP request from the **same** source |
| `HTTP 405` on TRACE | Nginx does not allow TRACE | Expected; `HTTP_UNCOMMON_METHOD` may still alert on incoming TRACE request |
| `iptables ... --line-numberssudo` | Two shell commands pasted on one line | Put `sudo docker compose logs ...` on a new line |
| IP/target subnet changed | Docker recreated network; old dynamic IPs changed | Use `docker compose exec attacker hostname -i`; recheck Dashboard source IP and current policies |

To inspect current app status:

```bash
sudo docker compose ps -a
sudo docker compose logs --tail=100 sensor
sudo docker compose logs --tail=100 dashboard
sudo docker compose logs --tail=100 enforcer
```

### Fresh-state reset (optional; permanently deletes project runtime records)

The **GitHub ZIP contains no stored alert or incident data**. On a **new Docker host** this starts with an empty database. On a host where you already ran `name: netsentry`, Docker may reuse the existing named volume and its data; use this reset only if you intentionally want to erase that previous project data.

For an existing local installation only, run:

```bash
sudo bash scripts/reset_lab_data.sh
```

Read the warning and type `RESET NETSENTRY` to confirm. This stops **only this named Compose project**, deletes its own SQLite database files (alert/incident/policy history) from its named volume, and restarts the services. It does **not** call `docker system prune`, `docker volume prune`, or `docker compose down -v`. **Back up important evidence before reset.**

## 9. Local developer verification

```bash
python3 -m unittest discover -s tests -v
python3 -m netsentry.config
for f in scripts/*.sh; do bash -n "$f"; done
```

Release source verification: **61 tests passed/executed, 3 Flask integration tests skipped** in the artifact build environment; 25-rule config validated; Python compiled; shell syntax checked. **A full live Docker/browser test is not available in the release-building environment.** Run the integration and firewall tests on your own Kali host before a demonstration.

## 10. Publish a clean repository to GitHub

This release archive contains **source code, configuration, documentation, test scripts and empty placeholder directories only**—not a SQLite database, local IP history, real incident records, PCAP evidence or Docker volume contents.

**Via GitHub website:** Create an empty repository → **Add file → Upload files** → open the extracted `NetSentry-Cyber-Range` directory → upload its **contents** (including `compose.yaml`, `netsentry/`, `scripts/`, `tests/` and `README.md`). GitHub does not execute your Docker containers when you upload the files. Review the file list before committing; do not upload `*.db`, `*.pcap`, `.env` or `__pycache__/`.

**Via Git CLI (recommended for future one-folder updates):**

```bash
cd ~/Downloads/NetSentry-Cyber-Range
git init
git add .
git status                  # verify no database, packet captures or secrets
git commit -m "Initial clean NetSentry Cyber Range release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

Create the empty repository on GitHub first. Replace `YOUR_USERNAME/YOUR_REPO`. GitHub may request a personal access token or an authenticated credential helper. Future edits can stay in this **same local folder** and be committed with `git add`, `git commit` and `git push`—no repeated ZIP extraction is needed.

## 11. Project limitations and safe-use scope

- Designed for one **isolated Docker lab target**; no external scanning is required or intended.
- Only the lab target's **network namespace** is firewalled; the Kali host firewall is untouched.
- The `NETSENTRY` chain uses IPv4. Traffic patterns, rate-limit heuristics and packet counts are not proof of compromise.
- No production authentication, HTTPS termination, secret management or distributed sensor collection.
- Incidents and containment actions remain human-controlled. The dashboard is bound to **127.0.0.1**, and should stay that way.
- Respect licenses of Docker base images, Flask, Scapy, Nginx and other dependencies.

**Suggested university demo:** fresh start → generate benign HTTP → scan the lab target → inspect alerts and evidence → Analyze IP → create incident → Observe/Block → demonstrate firewall DROP counters → Release → show normal HTTP communication restored → run the 25-rule trigger suite separately.
