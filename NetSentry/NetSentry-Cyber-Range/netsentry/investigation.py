"""Explainable lab-only risk assessment and human-managed incident cases."""
import ipaddress
import sqlite3
import time
from collections import Counter
from .storage import connect

STATUSES = {'open', 'investigating', 'resolved'}


def validate_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise ValueError('Invalid IP address') from None


def risk_assessment(ip, db_path=None, now=None):
    """Deterministic advisory score; not a probability of compromise."""
    ip = validate_ip(ip)
    now = time.time() if now is None else now
    with connect(db_path) as db:
        rows = db.execute('''SELECT timestamp,rule_id,severity FROM alerts
           WHERE source_ip=? AND timestamp>=? AND timestamp<=?
           ORDER BY timestamp DESC LIMIT 1000''', (ip, now-86400, now)).fetchall()
    if not rows:
        return {'score': 0, 'level': 'No recent alerts', 'window_hours': 24, 'count': 0, 'unique_rules': 0, 'factors': [], 'last_alert': None}
    severities = Counter(r['severity'] for r in rows)
    unique = len(set(r['rule_id'] for r in rows))
    recent = sum(r['timestamp'] >= now-900 for r in rows)
    factors = [
        {'name':'High-severity alerts (24h)', 'value':severities['High'], 'points':min(30, severities['High']*10)},
        {'name':'Medium-severity alerts (24h)', 'value':severities['Medium'], 'points':min(15, severities['Medium']*3)},
        {'name':'Distinct triggered rules (24h)', 'value':unique, 'points':min(25, unique*5)},
        {'name':'Alert frequency (24h)', 'value':len(rows), 'points':min(20, len(rows)//3*4)},
        {'name':'Alerts in last 15 minutes', 'value':recent, 'points':min(10, recent*2)},
    ]
    score = sum(f['points'] for f in factors)
    level = 'High' if score >= 70 else 'Medium' if score >= 35 else 'Low'
    return {'score':score,'level':level,'window_hours':24,'count':len(rows),
            'unique_rules':unique,'last_alert':rows[0]['timestamp'],'factors':factors,
            'note':'Heuristic prioritization only; not proof of an attack or compromise.'}


def initialize_incidents(db_path=None):
    with connect(db_path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT NOT NULL,
          title TEXT NOT NULL, status TEXT NOT NULL,
          assigned_to TEXT NOT NULL, created_at REAL NOT NULL,
          updated_at REAL NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS incident_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
          at REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
          note TEXT NOT NULL, FOREIGN KEY(incident_id) REFERENCES incidents(id))''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip,updated_at DESC)')


def _clean(value, max_length, field, required=True):
    if not isinstance(value, str):
        raise ValueError(field + ' must be text')
    value=value.strip()
    if (required and not value) or len(value)>max_length:
        raise ValueError(field + ' must be between 1 and '+str(max_length)+' characters')
    return value


def list_incidents(ip, db_path=None):
    ip = validate_ip(ip)
    with connect(db_path) as db:
        cases=[dict(r) for r in db.execute('SELECT * FROM incidents WHERE source_ip=? ORDER BY updated_at DESC LIMIT 100', (ip,))]
        if cases:
            ids=[c['id'] for c in cases]
            marks=','.join('?' for _ in ids)
            events=[dict(r) for r in db.execute(f'SELECT * FROM incident_events WHERE incident_id IN ({marks}) ORDER BY at DESC,id DESC LIMIT 300',ids)]
        else: events=[]
    return {'incidents':cases,'events':events}


def create_incident(ip, title, actor, note, db_path=None):
    ip=validate_ip(ip)
    title=_clean(title,120,'Title')
    actor=_clean(actor,60,'Analyst')
    note=_clean(note,1000,'Note')
    now=time.time()
    with connect(db_path) as db:
        if not db.execute('SELECT 1 FROM alerts WHERE source_ip=? LIMIT 1',(ip,)).fetchone():
            raise ValueError('IP has no recorded alert')
        cur=db.execute('INSERT INTO incidents(source_ip,title,status,assigned_to,created_at,updated_at) VALUES(?,?,?,?,?,?)',(ip,title,'open',actor,now,now))
        id_=cur.lastrowid
        db.execute('INSERT INTO incident_events(incident_id,at,actor,action,note) VALUES(?,?,?,?,?)',(id_,now,actor,'created',note))
    return {'id':id_,'status':'open'}


def update_incident(ip, incident_id, actor, status, note, db_path=None):
    ip=validate_ip(ip)
    actor=_clean(actor,60,'Analyst')
    note=_clean(note,1000,'Note')
    if status not in STATUSES:
        raise ValueError('Invalid incident status')
    try:
        incident_id=int(incident_id)
    except (ValueError, TypeError):
        raise ValueError('Invalid incident ID') from None
    now=time.time()
    with connect(db_path) as db:
        old=db.execute('SELECT status FROM incidents WHERE source_ip=? AND id=?',(ip,incident_id)).fetchone()
        if old is None: raise ValueError('Incident not found for IP')
        db.execute('UPDATE incidents SET status=?,assigned_to=?,updated_at=? WHERE id=?',(status,actor,now,incident_id))
        db.execute('INSERT INTO incident_events(incident_id,at,actor,action,note) VALUES(?,?,?,?,?)',(incident_id,now,actor,'status: '+old['status']+' -> '+status,note))
    return {'id':incident_id,'status':status}


def traffic_analysis(ip, db_path=None, since_seconds=3600):
    ip=validate_ip(ip)
    cutoff=time.time()-since_seconds
    with connect(db_path) as db:
        buckets=[dict(r) for r in db.execute('''SELECT CAST(ts/60 AS INTEGER)*60 AS minute,COUNT(*) AS n
          FROM packet_events WHERE src=? AND ts>=? GROUP BY CAST(ts/60 AS INTEGER) ORDER BY minute''',(ip,cutoff))]
        ports=[dict(r) for r in db.execute('''SELECT protocol,dport,COUNT(*) AS n
          FROM packet_events WHERE src=? AND ts>=? AND dport IS NOT NULL
          GROUP BY protocol,dport ORDER BY n DESC LIMIT 12''',(ip,cutoff))]
        destinations=[dict(r) for r in db.execute('''SELECT dst,COUNT(*) AS n FROM packet_events
          WHERE src=? AND ts>=? GROUP BY dst ORDER BY n DESC LIMIT 10''',(ip,cutoff))]
        protocols=[dict(r) for r in db.execute('''SELECT protocol,COUNT(*) AS n FROM packet_events
          WHERE src=? AND ts>=? GROUP BY protocol ORDER BY n DESC''',(ip,cutoff))]
    return {'window_seconds':since_seconds,'timeline':buckets,'ports':ports,'destinations':destinations,'protocols':protocols,
            'note':'Based on retained sampled/inbound packet metadata; not complete network flow coverage.'}
