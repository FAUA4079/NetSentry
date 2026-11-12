"""Shared SQLite store for alerts and aggregated packet counters."""
import os
import sqlite3
import time

DB = os.environ.get('NETSENTRY_DB', '/data/netsentry.db')


def connect(db_path=None):
    db = sqlite3.connect(db_path or DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=15000')
    return db


def initialize(db_path=None):
    with connect(db_path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp REAL NOT NULL, source_ip TEXT NOT NULL,
          rule_id TEXT NOT NULL, activity TEXT NOT NULL,
          severity TEXT NOT NULL, details TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS packet_counts (
          bucket INTEGER NOT NULL, protocol TEXT NOT NULL,
          count INTEGER NOT NULL, PRIMARY KEY(bucket,protocol))''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip,id DESC)')
        db.execute('''CREATE TABLE IF NOT EXISTS packet_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
          src TEXT NOT NULL, dst TEXT NOT NULL, protocol TEXT NOT NULL,
          sport INTEGER, dport INTEGER, size INTEGER NOT NULL,
          tcp_flags INTEGER, icmp_type INTEGER, dns_qname TEXT,
          http_method TEXT, http_path TEXT)''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_packet_source ON packet_events(src,id DESC)')
    from .response import initialize_response
    initialize_response(db_path)
    from .investigation import initialize_incidents
    initialize_incidents(db_path)


def write_batch(counts, alerts, db_path=None, packet_events=None):
    if not counts and not alerts and not packet_events:
        return
    with connect(db_path) as db:
        for (bucket, protocol), count in counts.items():
            db.execute('''INSERT INTO packet_counts(bucket,protocol,count) VALUES(?,?,?)
              ON CONFLICT(bucket,protocol) DO UPDATE SET count=count+excluded.count''',
                       (bucket, protocol, count))
        db.executemany('''INSERT INTO alerts
          (timestamp,source_ip,rule_id,activity,severity,details)
          VALUES (?,?,?,?,?,?)''', [
            (a.timestamp, a.source_ip, a.rule_id, a.activity, a.severity, a.details)
            for a in alerts])
        if packet_events:
            db.executemany('''INSERT INTO packet_events
              (ts,src,dst,protocol,sport,dport,size,tcp_flags,icmp_type,dns_qname,http_method,http_path)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', packet_events)
        # Keep history bounded for a classroom demo.
        old = int(time.time()) - 7 * 24 * 3600
        db.execute('DELETE FROM packet_counts WHERE bucket < ?', (old,))
        # Keep only the most recent 24h of packet metadata; no packet payloads are stored.
        if packet_events:
            db.execute('DELETE FROM packet_events WHERE ts < ?', (time.time() - 86400,))
            # Global maximum of 100,000 packet-event records in the lab database.
            db.execute('''DELETE FROM packet_events WHERE id <= (
              SELECT COALESCE(MAX(id),0)-100000 FROM packet_events)''')


def _where_time(column, start=None, end=None, severity=None):
    # Build a parameterized, inclusive time-bound condition.
    clauses = []
    args = []
    if start is not None:
        clauses.append(f'{column} >= ?')
        args.append(start)
    if end is not None:
        clauses.append(f'{column} <= ?')
        args.append(end)
    if severity is not None:
        clauses.append('severity = ?')
        args.append(severity)
    return clauses, args


def read_dashboard(db_path=None, *, alert_start=None, alert_end=None, alert_severity=None,
                   alert_limit=30, alert_offset=0):
    # Totals remain cumulative; recent alerts use bounded server-side pagination.
    if not 1 <= alert_limit <= 100 or not 0 <= alert_offset <= 1000000:
        raise ValueError('Invalid alert pagination')
    clauses, args = _where_time('timestamp', alert_start, alert_end, alert_severity)
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with connect(db_path) as db:
        total = db.execute('SELECT COALESCE(SUM(count),0) FROM packet_counts').fetchone()[0]
        alerts_total = db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        protocols = {r['protocol']: r['n'] for r in db.execute('''
            SELECT protocol, SUM(count) AS n FROM packet_counts
            GROUP BY protocol ORDER BY n DESC''')}
        filtered_total = db.execute('SELECT COUNT(*) FROM alerts ' + where, args).fetchone()[0]
        recent = [dict(r) for r in db.execute('''
            SELECT id,timestamp,source_ip,rule_id,activity,severity,details
            FROM alerts ''' + where + ' ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?', [*args, alert_limit, alert_offset])]
        current_minute = int(time.time()) // 60 * 60
        timeline = [dict(r) for r in db.execute('''
            SELECT (bucket / 60) * 60 AS minute, SUM(count) AS n
            FROM packet_counts WHERE bucket >= ?
            GROUP BY (bucket / 60) * 60 ORDER BY minute''', (current_minute - 19 * 60,))]
    return {'total_packets': total, 'total_alerts': alerts_total,
            'filtered_alerts': filtered_total, 'alert_offset': alert_offset,
            'alert_limit': alert_limit, 'protocols': protocols,
            'alerts': recent, 'timeline': timeline}


def read_observation(ip, db_path=None, *, alert_start=None, alert_end=None,
                     alert_severity=None, packet_start=None, packet_end=None, packet_protocol=None):
    # Query only the requested time spans, with bounded returned rows.
    from .response import valid_ip
    ip = valid_ip(ip)
    alert_filters, alert_args = _where_time('timestamp', alert_start, alert_end, alert_severity)
    packet_filters, packet_args = _where_time('ts', packet_start, packet_end)
    if packet_protocol and packet_protocol != 'all':
        if packet_protocol not in ('TCP', 'UDP', 'ICMP', 'OTHER'):
            raise ValueError('Invalid packet protocol')
        packet_filters.append('protocol = ?')
        packet_args.append(packet_protocol)
    awhere = 'source_ip=?' + ''.join(' AND ' + f for f in alert_filters)
    pwhere = 'src=?' + ''.join(' AND ' + f for f in packet_filters)
    ap = [ip, *alert_args]
    pp = [ip, *packet_args]
    with connect(db_path) as db:
        alerts = [dict(r) for r in db.execute('SELECT * FROM alerts WHERE ' + awhere +
                 ' ORDER BY timestamp DESC,id DESC LIMIT 200', ap)]
        packets = [dict(r) for r in db.execute('SELECT * FROM packet_events WHERE ' + pwhere +
                  ' ORDER BY ts DESC,id DESC LIMIT 200', pp)]
        policy = db.execute('SELECT * FROM ip_policies WHERE ip=?', (ip,)).fetchone()
        has_drop_table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='firewall_drop_counters'").fetchone()
        drop_row = (db.execute('SELECT * FROM firewall_drop_counters WHERE ip=?', (ip,)).fetchone()
                    if has_drop_table else None)

        audit = [dict(r) for r in db.execute('''SELECT * FROM response_audit
          WHERE ip=? ORDER BY id DESC LIMIT 100''', (ip,))]
        counts = {r['protocol']: r['n'] for r in db.execute(
            'SELECT protocol,COUNT(*) n FROM packet_events WHERE ' + pwhere +
            ' GROUP BY protocol', pp)}
        total_alerts = db.execute('SELECT COUNT(*) FROM alerts WHERE source_ip=?', (ip,)).fetchone()[0]
        total_packets = db.execute('SELECT COUNT(*) FROM packet_events WHERE src=?', (ip,)).fetchone()[0]
        matching_alerts = db.execute('SELECT COUNT(*) FROM alerts WHERE ' + awhere, ap).fetchone()[0]
        matching_packets = db.execute('SELECT COUNT(*) FROM packet_events WHERE ' + pwhere, pp).fetchone()[0]
        by_rule = [dict(r) for r in db.execute('SELECT rule_id, COUNT(*) n FROM alerts WHERE ' +
                   awhere + ' GROUP BY rule_id ORDER BY n DESC', ap)]
    return {'ip': ip, 'alerts': alerts, 'packets': packets, 'policy': dict(policy) if policy else None,
            'audit': audit, 'protocols': counts, 'by_rule': by_rule,
            'firewall_drops': dict(drop_row) if drop_row else None,
            'total_alerts': total_alerts, 'stored_packet_events': total_packets,
            'matching_alerts': matching_alerts, 'matching_packets': matching_packets}


def read_suspicious_ips(db_path=None, limit=500):
    """One summary per alerting IP, latest evidence first (no duplicate log rows)."""
    if not 1 <= limit <= 500:
        raise ValueError('Invalid suspicious IP limit')
    with connect(db_path) as db:
        return [dict(r) for r in db.execute('''
            SELECT a.source_ip, a.timestamp, a.rule_id, a.activity,
                   a.details, a.severity, s.alert_count
            FROM alerts AS a
            JOIN (SELECT source_ip, MAX(id) AS latest_id, COUNT(*) AS alert_count
                  FROM alerts GROUP BY source_ip) AS s
              ON a.id=s.latest_id
            ORDER BY a.timestamp DESC, a.id DESC LIMIT ?''', (limit,))]
