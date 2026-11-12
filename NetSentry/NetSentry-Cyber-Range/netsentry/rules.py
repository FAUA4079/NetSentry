"""Explainable threshold rules using parsed packet metadata (no AI inference)."""
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional
import math
from urllib.parse import urlsplit


@dataclass(frozen=True)
class PacketRecord:
    ts: float
    src: str
    dst: str
    protocol: str
    dport: Optional[int] = None
    tcp_syn: bool = False
    icmp_echo_request: bool = False
    sport: Optional[int] = None
    size: int = 0
    tcp_flags: Optional[int] = None
    fragmented: bool = False
    icmp_type: Optional[int] = None
    dns_qname: str = ""
    dns_qtype: Optional[int] = None
    dns_rcode: Optional[int] = None
    dns_is_response: bool = False
    http_method: str = ""
    http_path: str = ""
    http_user_agent: str = ""
    http_host: str = ""


@dataclass(frozen=True)
class Alert:
    timestamp: float
    source_ip: str
    rule_id: str
    activity: str
    severity: str
    details: str


ALL_RULES = ('PORT_SCAN', 'TRAFFIC_SPIKE', 'RESTRICTED_PORT', 'SYN_BURST', 'ICMP_ECHO_FLOOD', 'UDP_PORT_SCAN', 'UDP_BURST', 'TCP_RST_BURST', 'TCP_FIN_SCAN', 'TCP_NULL_SCAN', 'TCP_XMAS_SCAN', 'TCP_ACK_PROBE', 'IP_FRAGMENT', 'ICMP_LARGE_ECHO', 'ICMP_UNREACH_BURST', 'DNS_QUERY_BURST', 'DNS_LONG_QUERY', 'DNS_HIGH_ENTROPY_LABEL', 'DNS_TXT_BURST', 'DNS_UNIQUE_NAME_BURST', 'DNS_NXDOMAIN_BURST', 'HTTP_SENSITIVE_PATH', 'HTTP_UNCOMMON_METHOD', 'HTTP_LONG_URI', 'HTTP_SCANNER_USER_AGENT')
DEFAULT_THRESHOLDS = {'UDP_PORT_SCAN': (12, 15), 'UDP_BURST': (80, 10), 'TCP_RST_BURST': (30, 10), 'TCP_ACK_PROBE': (12, 15), 'ICMP_LARGE_ECHO': (1200, 0), 'ICMP_UNREACH_BURST': (15, 10), 'DNS_QUERY_BURST': (35, 10), 'DNS_LONG_QUERY': (90, 0), 'DNS_HIGH_ENTROPY_LABEL': (20, 350), 'DNS_TXT_BURST': (15, 10), 'DNS_UNIQUE_NAME_BURST': (25, 15), 'DNS_NXDOMAIN_BURST': (15, 10), 'HTTP_LONG_URI': (512, 0)}

class RuleEngine:
    def __init__(self, scan_ports=10, scan_window=15, rate_packets=60,
                 rate_window=10, cooldown=30, prohibited_ports=(22, 23, 445),
                 syn_packets=80, syn_window=10, icmp_packets=20, icmp_window=10,
                 enabled=None, thresholds=None):
        self.scan_ports = scan_ports
        self.scan_window = scan_window
        self.rate_packets = rate_packets
        self.rate_window = rate_window
        self.cooldown = cooldown
        self.prohibited_ports = set(prohibited_ports)
        self.syn_packets = syn_packets
        self.syn_window = syn_window
        self.icmp_packets = icmp_packets
        self.icmp_window = icmp_window
        self.enabled = set(ALL_RULES) if enabled is None else set(enabled)
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.events = defaultdict(deque)
        self.unique_events = defaultdict(deque)
        self.syn_bursts = defaultdict(deque)
        self.icmp_events = defaultdict(deque)
        self.syns = defaultdict(deque)
        self.traffic = defaultdict(deque)
        self.last_alert = {}

    def _can_alert(self, rule, src, now):
        key = (rule, src)
        if now - self.last_alert.get(key, float('-inf')) < self.cooldown:
            return False
        self.last_alert[key] = now
        return True

    def process(self, p: PacketRecord):
        """Process only inbound packets addressed to the target (caller filters)."""
        alerts = []
        q = self.traffic[p.src]
        q.append(p.ts)
        while q and q[0] < p.ts - self.rate_window:
            q.popleft()
        if 'TRAFFIC_SPIKE' in self.enabled and len(q) >= self.rate_packets and self._can_alert('TRAFFIC_SPIKE', p.src, p.ts):
            alerts.append(Alert(p.ts, p.src, 'TRAFFIC_SPIKE', 'High traffic volume',
                                'Medium', f'{len(q)} incoming packets in {self.rate_window}s'))

        if p.protocol == 'TCP' and p.tcp_syn and p.dport is not None:
            synq = self.syns[p.src]
            synq.append((p.ts, p.dport))
            while synq and synq[0][0] < p.ts - self.scan_window:
                synq.popleft()
            unique = len({port for _, port in synq})
            if 'PORT_SCAN' in self.enabled and unique >= self.scan_ports and self._can_alert('PORT_SCAN', p.src, p.ts):
                alerts.append(Alert(p.ts, p.src, 'PORT_SCAN', 'Possible TCP port scan',
                                    'High', f'{unique} distinct destination ports in {self.scan_window}s'))
            if 'RESTRICTED_PORT' in self.enabled and p.dport in self.prohibited_ports and self._can_alert('RESTRICTED_PORT', p.src, p.ts):
                alerts.append(Alert(p.ts, p.src, 'RESTRICTED_PORT', 'Restricted service connection attempt',
                                    'Medium', f'TCP SYN toward policy-restricted port {p.dport}; access not confirmed'))
            burst = self.syn_bursts[(p.src, p.dst)]
            burst.append(p.ts)
            while burst and burst[0] < p.ts - self.syn_window:
                burst.popleft()
            if 'SYN_BURST' in self.enabled and len(burst) >= self.syn_packets and self._can_alert('SYN_BURST', p.src, p.ts):
                alerts.append(Alert(p.ts, p.src, 'SYN_BURST', 'High TCP SYN attempt rate',
                                    'High', f'{len(burst)} SYN attempts in {self.syn_window}s; not proof of DoS'))
        if p.protocol == 'ICMP' and p.icmp_echo_request:
            qicmp = self.icmp_events[(p.src, p.dst)]
            qicmp.append(p.ts)
            while qicmp and qicmp[0] < p.ts - self.icmp_window:
                qicmp.popleft()
            if 'ICMP_ECHO_FLOOD' in self.enabled and len(qicmp) >= self.icmp_packets and self._can_alert('ICMP_ECHO_FLOOD', p.src, p.ts):
                alerts.append(Alert(p.ts, p.src, 'ICMP_ECHO_FLOOD', 'High ICMP echo-request rate',
                                    'Medium', f'{len(qicmp)} echo requests in {self.icmp_window}s; may be benign testing'))
        alerts.extend(self._extended_rules(p))
        return alerts

    def _alert(self, p, rule, activity, severity, details):
        if rule not in self.enabled or not self._can_alert(rule, p.src, p.ts):
            return []
        return [Alert(p.ts, p.src, rule, activity, severity, details)]

    def _threshold(self, rule):
        return self.thresholds[rule]

    def _count(self, rule, p, *, key=None, eligible=True):
        if not eligible or rule not in self.enabled:
            return False, 0
        count, window = self._threshold(rule)
        k = (rule, p.src, p.dst) if key is None else (rule, *key)
        q = self.events[k]
        q.append(p.ts)
        while q and q[0] < p.ts - window:
            q.popleft()
        return len(q) >= count, len(q)

    def _unique_count(self, rule, p, value, *, key=None, eligible=True):
        if not eligible or rule not in self.enabled:
            return False, 0
        count, window = self._threshold(rule)
        k = (rule, p.src, p.dst) if key is None else (rule, *key)
        q = self.unique_events[k]
        q.append((p.ts, value))
        while q and q[0][0] < p.ts - window:
            q.popleft()
        unique = len({v for _, v in q})
        return unique >= count, unique

    def _extended_rules(self, p):
        a = []
        def emit(rule, activity, severity, info):
            a.extend(self._alert(p, rule, activity, severity, info))

        if p.protocol == 'UDP':
            ok, n = self._unique_count('UDP_PORT_SCAN', p, p.dport, eligible=p.dport is not None)
            if ok:
                emit('UDP_PORT_SCAN', 'Possible UDP service scan', 'Medium', f'{n} distinct UDP destination ports')
            ok, n = self._count('UDP_BURST', p)
            if ok:
                emit('UDP_BURST', 'High UDP packet rate', 'Medium', f'{n} UDP datagrams (may be legitimate)')

        if p.protocol == 'TCP':
            flags = p.tcp_flags
            ok, n = self._count('TCP_RST_BURST', p, eligible=flags is not None and bool(flags & 0x04))
            if ok:
                emit('TCP_RST_BURST', 'High TCP reset rate', 'Medium', f'{n} TCP RST packets')
            if flags is not None and p.dport is not None:
                # Exact stealth scan flag combinations, only count first matching SYN-less packet.
                signatures = [('TCP_FIN_SCAN', 0x01), ('TCP_NULL_SCAN', 0x00), ('TCP_XMAS_SCAN', 0x29)]
                for rule, value in signatures:
                    if flags == value:
                        emit(rule, f'Possible {rule.replace("TCP_", "").replace("_", " ").lower()} probe', 'Medium', f'TCP flags=0x{flags:02x}, destination port {p.dport}; packet alone is not proof of scanning')
                # ACK probe is a bare ACK with no data, often sent to uncommon ports.
                if flags == 0x10 and p.size <= 80:
                    ok, n = self._unique_count('TCP_ACK_PROBE', p, p.dport)
                    if ok:
                        emit('TCP_ACK_PROBE', 'Possible TCP ACK reconnaissance', 'Medium', f'{n} distinct ports received small ACK-only packets')
            if p.fragmented:
                emit('IP_FRAGMENT', 'Fragmented IP packet observed', 'Low', 'Fragmented packet received; may be benign or an evasion indicator')

        if p.protocol != 'TCP' and p.fragmented:
            emit('IP_FRAGMENT', 'Fragmented IP packet observed', 'Low', 'Fragmented packet received; may be benign or an evasion indicator')

        if p.protocol == 'ICMP':
            if p.icmp_echo_request and p.size >= self._threshold('ICMP_LARGE_ECHO')[0]:
                emit('ICMP_LARGE_ECHO', 'Unusually large ICMP echo request', 'Low', f'{p.size} byte IP packet')
            ok, n = self._count('ICMP_UNREACH_BURST', p, eligible=p.icmp_type == 3)
            if ok:
                emit('ICMP_UNREACH_BURST', 'ICMP destination unreachable burst', 'Medium', f'{n} ICMP type 3 packets')

        if p.dns_qname and not p.dns_is_response:
            domain = p.dns_qname.strip('.').lower()
            ok, n = self._count('DNS_QUERY_BURST', p)
            if ok:
                emit('DNS_QUERY_BURST', 'High DNS request rate', 'Medium', f'{n} DNS questions')
            if len(domain) >= self._threshold('DNS_LONG_QUERY')[0]:
                emit('DNS_LONG_QUERY', 'Long DNS query name', 'Low', f'Domain length={len(domain)} characters')
            labels = domain.split('.')
            longest = max(labels, key=len, default='')
            if len(longest) >= self._threshold('DNS_HIGH_ENTROPY_LABEL')[0] and _entropy(longest) >= self._threshold('DNS_HIGH_ENTROPY_LABEL')[1] / 100:
                emit('DNS_HIGH_ENTROPY_LABEL', 'High entropy DNS label', 'Medium', f'Label length={len(longest)}, entropy={_entropy(longest):.2f} bits/char')
            ok, n = self._count('DNS_TXT_BURST', p, eligible=p.dns_qtype == 16)
            if ok:
                emit('DNS_TXT_BURST', 'Burst of DNS TXT queries', 'Medium', f'{n} TXT requests')
            # Approximation: distinct full names (not proof they share a common parent).
            ok, n = self._unique_count('DNS_UNIQUE_NAME_BURST', p, domain)
            if ok:
                emit('DNS_UNIQUE_NAME_BURST', 'Many unique DNS names', 'Medium', f'{n} distinct queried names')
        if p.dns_is_response and p.dns_rcode == 3:
            ok, n = self._count('DNS_NXDOMAIN_BURST', p)
            if ok:
                emit('DNS_NXDOMAIN_BURST', 'Many negative DNS responses', 'Medium', f'{n} NXDOMAIN responses from source (likely DNS resolver)')

        if p.protocol == 'TCP' and p.http_method:
            path = p.http_path[:4096]
            normalized = urlsplit(path).path.lower()
            suspicious = ('/.env', '/.git/', '/wp-admin', '/phpmyadmin', '/server-status', '/actuator/env', '/config.php')
            if any(normalized == s.rstrip('/') or normalized.startswith(s) for s in suspicious):
                emit('HTTP_SENSITIVE_PATH', 'Request for potentially sensitive web path', 'Medium', f'Method={p.http_method}, path={path[:150]}')
            if p.http_method.upper() in {'TRACE', 'TRACK', 'CONNECT'}:
                emit('HTTP_UNCOMMON_METHOD', 'Uncommon HTTP request method', 'Low', f'Method={p.http_method}, path={path[:150]}')
            if len(path) >= self._threshold('HTTP_LONG_URI')[0]:
                emit('HTTP_LONG_URI', 'Unusually long HTTP request target', 'Low', f'URI length={len(path)}')
            ua = p.http_user_agent.lower()
            if any(sig in ua for sig in ('sqlmap', 'nikto', 'nmap scripting engine', 'nuclei', 'gobuster', 'dirbuster')):
                emit('HTTP_SCANNER_USER_AGENT', 'Known scanner user-agent string', 'Medium', f'User-Agent={p.http_user_agent[:150]} (spoofable)')
        return a


def _entropy(value):
    if not value:
        return 0.0
    return -sum((value.count(c) / len(value)) * math.log2(value.count(c) / len(value)) for c in set(value))
