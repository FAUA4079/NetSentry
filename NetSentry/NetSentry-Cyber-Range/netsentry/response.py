"""Human-reviewed containment policy state. No host firewall access."""
import ipaddress
import sqlite3
import time
from .storage import connect

MODES = {'observe', 'blocked', 'released'}


def initialize_response(db_path=None):
    with connect(db_path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS ip_policies (
          ip TEXT PRIMARY KEY, mode TEXT NOT NULL,
          updated_at REAL NOT NULL, reason TEXT NOT NULL,
          apply_state TEXT NOT NULL DEFAULT 'pending',
          apply_error TEXT NOT NULL DEFAULT '', applied_at REAL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS response_audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
          ip TEXT NOT NULL, prior_mode TEXT, new_mode TEXT NOT NULL,
          reason TEXT NOT NULL, actor TEXT NOT NULL)""")


def valid_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError('A valid IPv4 address is required') from None
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError('Only IPv4 is supported')
    return str(address)


def request_action(ip, mode, reason, actor='dashboard-operator', db_path=None):
    ip = valid_ip(ip)
    if mode not in MODES:
        raise ValueError('Unknown action')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 250:
        raise ValueError('A reason between 1 and 250 characters is required')
    now = time.time()
    with connect(db_path) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT mode FROM ip_policies WHERE ip=?', (ip,)).fetchone()
        prior = row['mode'] if row else None
        if mode == 'released' and prior not in ('observe', 'blocked'):
            raise ValueError('IP is not under observation or blocked')
        if prior == mode:
            raise ValueError('IP is already in this mode')
        db.execute("""INSERT INTO ip_policies(ip, mode, updated_at, reason, apply_state, apply_error, applied_at)
          VALUES (?, ?, ?, ?, 'pending', '', NULL)
          ON CONFLICT(ip) DO UPDATE SET mode=excluded.mode, updated_at=excluded.updated_at,
          reason=excluded.reason, apply_state='pending', apply_error='', applied_at=NULL""",
                   (ip, mode, now, reason.strip()))
        db.execute("""INSERT INTO response_audit(at,ip,prior_mode,new_mode,reason,actor)
          VALUES(?,?,?,?,?,?)""", (now, ip, prior, mode, reason.strip(), actor))
    return {'ip': ip, 'mode': mode, 'apply_state': 'pending'}


def policies(db_path=None):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute('SELECT * FROM ip_policies ORDER BY updated_at DESC')]


def audit(db_path=None, limit=50):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute('SELECT * FROM response_audit ORDER BY id DESC LIMIT ?', (limit,))]


def mark_applied(ip, updated_at, status, message='', db_path=None):
    with connect(db_path) as db:
        db.execute("""UPDATE ip_policies SET apply_state=?, apply_error=?, applied_at=?
          WHERE ip=? AND updated_at=?""", (status, message[:500], time.time(), ip, updated_at))
