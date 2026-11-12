"""Safely read per-IP DROP counters from the target's isolated NETSENTRY iptables chain."""
import ipaddress
import time
from .storage import connect


def initialize_counters():
    with connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS firewall_drop_counters (
          ip TEXT PRIMARY KEY, dropped_packets INTEGER NOT NULL,
          dropped_bytes INTEGER NOT NULL, sampled_at REAL NOT NULL,
          mode TEXT NOT NULL)''')


def parse_drop_rules(output):
    totals = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 9 or not fields[0].isdigit() or not fields[1].isdigit() or fields[2] != 'DROP':
            continue
        try:
            addr = str(ipaddress.IPv4Address(fields[7].split('/')[0]))
        except ValueError:
            continue
        pkts, amount = totals.get(addr, (0, 0))
        totals[addr] = (pkts + int(fields[0]), amount + int(fields[1]))
    return totals


def save_snapshot(output, entries):
    counters = parse_drop_rules(output)
    active = {e['ip']: e['mode'] for e in entries if e['mode'] in ('observe', 'blocked') and e.get('apply_state') != 'error'}
    now = time.time()
    with connect() as db:
        db.execute('DELETE FROM firewall_drop_counters')
        db.executemany('''INSERT INTO firewall_drop_counters
          (ip, dropped_packets, dropped_bytes, sampled_at, mode) VALUES (?,?,?,?,?)''', [
            (ip, *counters.get(ip, (0, 0)), now, mode) for ip, mode in active.items()
        ])
