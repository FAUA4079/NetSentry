"""Live target-side packet capture and detection using Scapy."""
import logging
import os
import signal
import time
from collections import Counter

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, get_if_addr, sniff

from .rules import PacketRecord, RuleEngine
from .config import load_ruleset
from .storage import initialize, write_batch

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('netsentry.sensor')


def main():
    interface = os.getenv('NETSENTRY_INTERFACE', 'eth0')
    target_ip = get_if_addr(interface)
    LOG.info('Sensor started: interface=%s target_ip=%s', interface, target_ip)
    initialize()
    rule_path = os.getenv('NETSENTRY_RULESET', '/app/config/rules.json')
    engine = RuleEngine(**load_ruleset(rule_path))
    LOG.info('Loaded %d enabled rules from %s', len(engine.enabled), rule_path)
    counts = Counter()
    pending_alerts = []
    packet_events = []
    last_flush = time.monotonic()
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def handle(pkt):
        nonlocal last_flush
        if IP not in pkt:
            return
        ip = pkt[IP]
        protocol = ('TCP' if TCP in pkt else 'UDP' if UDP in pkt
                    else 'ICMP' if ICMP in pkt else 'OTHER')
        now = time.time()
        counts[(int(now) // 10 * 10, protocol)] += 1
        if ip.dst == target_ip:
            tcp = pkt[TCP] if TCP in pkt else None
            udp = pkt[UDP] if UDP in pkt else None
            icmp = pkt[ICMP] if ICMP in pkt else None
            dport = int(tcp.dport if tcp else udp.dport) if tcp or udp else None
            sport = int(tcp.sport if tcp else udp.sport) if tcp or udp else None
            flags = int(tcp.flags) if tcp else None
            syn = tcp is not None and flags & 0x12 == 0x02
            dns = pkt[DNS] if DNS in pkt else None
            question = dns.qd if dns and int(dns.qdcount) and DNSQR in pkt else None
            domain = ''
            if question is not None:
                rawname = question.qname
                domain = rawname.decode('utf-8', 'replace') if isinstance(rawname, bytes) else str(rawname)
            method, path, agent, host = '', '', '', ''
            if tcp is not None and Raw in pkt and int(tcp.dport) in (80, 8080, 8000):
                payload = bytes(pkt[Raw].load)[:8192]
                line = payload.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
                parts = line.split(' ')
                if len(parts) == 3 and parts[2].startswith('HTTP/1.') and parts[0].isalpha():
                    method, path = parts[0][:32], parts[1][:4096]
                    for header in payload.split(b'\r\n')[1:60]:
                        lower = header.lower()
                        if lower.startswith(b'user-agent:'):
                            agent = header.split(b':', 1)[1].strip().decode('latin-1', 'replace')[:512]
                        elif lower.startswith(b'host:'):
                            host = header.split(b':', 1)[1].strip().decode('latin-1', 'replace')[:255]
            record = PacketRecord(now, ip.src, ip.dst, protocol, dport, bool(syn),
                                  icmp is not None and int(icmp.type) == 8,
                                  sport=sport, size=int(ip.len) if int(ip.len) else len(bytes(ip)),
                                  tcp_flags=flags,
                                  fragmented=bool(int(ip.flags) & 1 or int(ip.frag) > 0),
                                  icmp_type=int(icmp.type) if icmp else None,
                                  dns_qname=domain,
                                  dns_qtype=int(question.qtype) if question else None,
                                  dns_rcode=int(dns.rcode) if dns else None,
                                  dns_is_response=bool(int(dns.qr)) if dns else False,
                                  http_method=method, http_path=path,
                                  http_user_agent=agent, http_host=host)
            packet_events.append((now, str(ip.src), str(ip.dst), protocol, sport, dport,
                                  record.size, flags, record.icmp_type,
                                  domain[:253], method[:32], path[:512]))
            for a in engine.process(record):
                pending_alerts.append(a)
                LOG.warning('%s %s %s — %s', a.rule_id, a.severity, a.source_ip, a.details)
        if time.monotonic() - last_flush >= 2:
            write_batch(counts, pending_alerts, packet_events=packet_events)
            counts.clear()
            pending_alerts.clear()
            packet_events.clear()
            last_flush = time.monotonic()

    # timeout allows clean shutdown & flush even when there is no traffic.
    while running:
        try:
            sniff(iface=interface, prn=handle, store=False, timeout=1)
        except Exception:
            LOG.exception('Capture failed; retrying')
            time.sleep(2)
        if counts or pending_alerts or packet_events:
            write_batch(counts, pending_alerts, packet_events=packet_events)
            counts.clear()
            pending_alerts.clear()
            packet_events.clear()
    LOG.info('Sensor stopped')


if __name__ == '__main__':
    main()
