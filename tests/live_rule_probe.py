#!/usr/bin/env python3
"""NetSentry v3 live lab-only rule probes.

Use only on the isolated netsentry_lab bridge, from a temporary container.
Examples:
  python live_rule_probe.py --list
  python live_rule_probe.py --rule TCP_FIN_SCAN
  python live_rule_probe.py --all
"""
import argparse
import ipaddress
import socket
import time

from scapy.all import DNS, DNSQR, ICMP, IP, Raw, TCP, UDP, fragment, send

RULES = [
    'PORT_SCAN', 'TRAFFIC_SPIKE', 'RESTRICTED_PORT', 'SYN_BURST',
    'ICMP_ECHO_FLOOD', 'UDP_PORT_SCAN', 'UDP_BURST', 'TCP_RST_BURST',
    'TCP_FIN_SCAN', 'TCP_NULL_SCAN', 'TCP_XMAS_SCAN', 'TCP_ACK_PROBE',
    'IP_FRAGMENT', 'ICMP_LARGE_ECHO', 'ICMP_UNREACH_BURST',
    'DNS_QUERY_BURST', 'DNS_LONG_QUERY', 'DNS_HIGH_ENTROPY_LABEL',
    'DNS_TXT_BURST', 'DNS_UNIQUE_NAME_BURST', 'DNS_NXDOMAIN_BURST',
    'HTTP_SENSITIVE_PATH', 'HTTP_UNCOMMON_METHOD', 'HTTP_LONG_URI',
    'HTTP_SCANNER_USER_AGENT',
]


def send_packets(packets):
    send(packets, inter=0.01, verbose=False)


def dns_query(dst, name, qtype=1, qr=0, rcode=0, index=0):
    # DNS packets addressed TO target: no DNS daemon required.
    if qr:
        return IP(dst=dst) / UDP(sport=53, dport=53000) / DNS(
            id=1000 + index, qr=1, rcode=rcode, qd=DNSQR(qname=name))
    return IP(dst=dst) / UDP(sport=40000 + index % 1000, dport=53) / DNS(
        id=1000 + index, rd=1, qd=DNSQR(qname=name, qtype=qtype))


def http_request(dst, method='GET', path='/', ua='NetSentry-Lab-Probe/1.0'):
    payload = (f'{method} {path} HTTP/1.1\r\nHost: target\r\n'
               f'User-Agent: {ua}\r\nConnection: close\r\n\r\n').encode()
    with socket.create_connection((dst, 80), timeout=3) as sock:
        sock.sendall(payload)
        try:
            sock.settimeout(0.5)
            sock.recv(1024)
        except (socket.timeout, ConnectionResetError):
            pass


def run_rule(rule, dst):
    if rule == 'PORT_SCAN':
        send_packets([IP(dst=dst)/TCP(sport=42000+i, dport=1000+i, flags='S') for i in range(12)])
    elif rule == 'TRAFFIC_SPIKE':
        send_packets([IP(dst=dst)/UDP(sport=43000+i, dport=9999)/Raw(load=b'test') for i in range(65)])
    elif rule == 'RESTRICTED_PORT':
        send_packets(IP(dst=dst)/TCP(sport=44000, dport=22, flags='S'))
    elif rule == 'SYN_BURST':
        send_packets([IP(dst=dst)/TCP(sport=45000+i, dport=3000+(i%4), flags='S') for i in range(85)])
    elif rule == 'ICMP_ECHO_FLOOD':
        send_packets([IP(dst=dst)/ICMP(type=8, id=1234, seq=i) for i in range(25)])
    elif rule == 'UDP_PORT_SCAN':
        send_packets([IP(dst=dst)/UDP(sport=46000+i, dport=20000+i)/Raw(load=b'test') for i in range(15)])
    elif rule == 'UDP_BURST':
        send_packets([IP(dst=dst)/UDP(sport=47000+i, dport=21000)/Raw(load=b'test') for i in range(85)])
    elif rule == 'TCP_RST_BURST':
        send_packets([IP(dst=dst)/TCP(sport=48000+i, dport=11000, flags='R') for i in range(35)])
    elif rule in ('TCP_FIN_SCAN', 'TCP_NULL_SCAN', 'TCP_XMAS_SCAN'):
        flags = {'TCP_FIN_SCAN':'F', 'TCP_NULL_SCAN':'', 'TCP_XMAS_SCAN':'FPU'}[rule]
        send_packets(IP(dst=dst)/TCP(sport=49000, dport=11001, flags=flags))
    elif rule == 'TCP_ACK_PROBE':
        send_packets([IP(dst=dst)/TCP(sport=50000+i, dport=22000+i, flags='A') for i in range(15)])
    elif rule == 'IP_FRAGMENT':
        packet = IP(dst=dst)/UDP(sport=5555,dport=5556)/Raw(load=b'A'*1900)
        send_packets(fragment(packet, fragsize=600))
    elif rule == 'ICMP_LARGE_ECHO':
        send_packets(IP(dst=dst)/ICMP(type=8)/Raw(load=b'A'*1300))
    elif rule == 'ICMP_UNREACH_BURST':
        send_packets([IP(dst=dst)/ICMP(type=3, code=3)/Raw(load=b'A'*8) for i in range(18)])
    elif rule == 'DNS_QUERY_BURST':
        send_packets([dns_query(dst, f'q{i}.test.invalid', index=i) for i in range(40)])
    elif rule == 'DNS_LONG_QUERY':
        name = ('a'*55)+'.'+('b'*50)+'.test.invalid'
        send_packets(dns_query(dst, name))
    elif rule == 'DNS_HIGH_ENTROPY_LABEL':
        send_packets(dns_query(dst, '0123456789abcdefghijklmnopqrstuv.test.invalid'))
    elif rule == 'DNS_TXT_BURST':
        send_packets([dns_query(dst, f'txt{i}.test.invalid', qtype=16, index=i) for i in range(18)])
    elif rule == 'DNS_UNIQUE_NAME_BURST':
        send_packets([dns_query(dst, f'unique{i}.test.invalid', index=i) for i in range(30)])
    elif rule == 'DNS_NXDOMAIN_BURST':
        send_packets([dns_query(dst, f'missing{i}.test.invalid', qr=1, rcode=3, index=i) for i in range(18)])
    elif rule == 'HTTP_SENSITIVE_PATH':
        http_request(dst, path='/.env')
    elif rule == 'HTTP_UNCOMMON_METHOD':
        http_request(dst, method='TRACE')
    elif rule == 'HTTP_LONG_URI':
        http_request(dst, path='/' + 'A'*550)
    elif rule == 'HTTP_SCANNER_USER_AGENT':
        http_request(dst, ua='sqlmap-lab-signature-test')
    else:
        raise ValueError(rule)


def main():
    parser = argparse.ArgumentParser(description='Isolated NetSentry v3 live rule testing')
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--all', action='store_true', help='Run all 25 probes')
    g.add_argument('--rule', choices=RULES, help='Run one named probe')
    g.add_argument('--list', action='store_true', help='Show available rule IDs')
    args = parser.parse_args()
    if args.list:
        for i, rule in enumerate(RULES, 1):
            print(f'{i:02d}. {rule}')
        return
    dst = socket.gethostbyname('target')
    if not ipaddress.ip_address(dst).is_private:
        parser.error('target must resolve to a private address on the lab network')
    source_ip = socket.gethostbyname(socket.gethostname())
    if not ipaddress.ip_address(source_ip).is_private:
        parser.error('probe source must be private')
    print(f'[+] Probe source: {source_ip}')
    print(f'[+] Target: target ({dst})')
    try:
        with socket.create_connection((dst, 80), timeout=3) as test_socket:
            test_socket.sendall(b'GET / HTTP/1.0\r\nHost: target\r\n\r\n')
            test_socket.settimeout(3)
            response=test_socket.recv(256)
        if b'HTTP/' not in response:
            raise RuntimeError('Target returned no HTTP response')
    except Exception as exc:
        print(f'[FATAL] Source {source_ip} cannot communicate with target: {exc}. Check blocking/observation policies.', flush=True)
        raise SystemExit(3)
    for rule in RULES if args.all else [args.rule]:
        print(f'[*] Probe: {rule}', flush=True)
        try:
            run_rule(rule, dst)
        except Exception as ex:
            print(f'[!] {rule}: {type(ex).__name__}: {ex}', flush=True)
        time.sleep(0.15)
    print('[+] Probe sequence finished. Check NetSentry sensor logs and dashboard; alerts may overlap or be cooldown-suppressed.')


if __name__ == '__main__':
    main()
