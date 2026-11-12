# Changelog

## v5.0.5 — Clean GitHub release

- Consolidates the latest v5 dashboard, investigation, policy enforcer and 25-rule engine into one self-contained source tree.
- Preserves the fix that registers Flask investigation routes **before** `app.run()`.
- Includes the latest Drop Packets/Drop Bytes analysis and time-preset filters without From/To inputs.
- Improves the 25-rule test runner with a fresh alert-ID baseline, controlled cooldown progress and targeted retries.
- When a test source cannot connect because an analyst blocked/observed it, prints lab policies/firewall counters and **does not** change security decisions.
- Includes optional *destructive* reset for this project's own runtime database, never unrelated Docker volumes.
- Replaces incremental update instructions with one complete installation, testing, troubleshooting and GitHub publishing README.
- Excludes local SQLite records, PCAP captures, runtime caches, backups and secrets.

**Validation:** 61 Python unit tests executed; 3 Flask integration tests skipped because Flask is not installed in the release build environment. The rule configuration, source compilation, shell syntax and embedded JavaScript syntax were checked. Full Docker/Flask/firewall integration must still be tested on a Docker host.
