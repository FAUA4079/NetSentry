"""Apply operator decisions ONLY to the target container network namespace.

Use a dedicated NETSENTRY chain in INPUT; never touch host firewall rules.
"""
import ipaddress
import logging
import os
import re
import signal
import subprocess
import time
from .response import policies, mark_applied
from .storage import initialize
from .firewall_metrics import initialize_counters, save_snapshot

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('netsentry.enforcer')
CHAIN = 'NETSENTRY'


def run(*args, check=True):
    return subprocess.run(['iptables', '-w', '3', *args], check=check, text=True, capture_output=True)


def target_subnet():
    output = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', 'eth0'],
                            check=True, text=True, capture_output=True).stdout
    cidrs = re.findall(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b', output)
    if not cidrs:
        raise RuntimeError('Cannot determine lab IPv4 network from eth0')
    interface = ipaddress.IPv4Interface(cidrs[0])
    # Prevent accidental use outside a private, container-specific network.
    if not interface.ip.is_private or interface.network.prefixlen < 16:
        raise RuntimeError('Refusing non-private or unusually broad target network')
    return interface.network, interface.ip


def ensure_chain():
    if run('-n', '-L', CHAIN, check=False).returncode != 0:
        run('-N', CHAIN)
    if run('-C', 'INPUT', '-j', CHAIN, check=False).returncode != 0:
        run('-I', 'INPUT', '1', '-j', CHAIN)


def mode_is_active(entry):
    return entry['mode'] in ('observe', 'blocked')


def apply_all(entries):
    network, own_ip = target_subnet()
    permitted = []
    for entry in entries:
        ip = ipaddress.ip_address(entry['ip'])
        if mode_is_active(entry) and (ip.version != 4 or ip not in network or ip == own_ip or ip.is_loopback):
            raise ValueError(f'Refusing IP outside target container lab network: {ip}')
        permitted.append(entry)
    ensure_chain()
    run('-F', CHAIN)
    # This chain sees incoming packets only. Blocked sources are dropped.
    for entry in permitted:
        ip, mode = entry['ip'], entry['mode']
        if mode == 'blocked':
            run('-A', CHAIN, '-s', ip, '-j', 'DROP')
        elif mode == 'observe':
            # Rate limit inbound packets from this IP: permit 5/sec burst 10,
            # then drop above quota. Other IPs are unaffected.
            name = 'ns_' + ip.replace('.', '_')
            run('-A', CHAIN, '-s', ip, '-m', 'hashlimit', '--hashlimit-upto', '5/second',
                '--hashlimit-burst', '10', '--hashlimit-mode', 'srcip',
                '--hashlimit-name', name, '-j', 'RETURN')
            run('-A', CHAIN, '-s', ip, '-j', 'DROP')
    # RELEASED sources receive no rule, so normal communication resumes.


def main():
    initialize()
    initialize_counters()
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last = None
    while not stopping:
        entries = policies()
        signature = tuple(sorted((e['ip'], e['mode'], e['updated_at']) for e in entries))
        if signature != last or any(e['apply_state'] == 'pending' for e in entries):
            try:
                network, own_ip = target_subnet()
                valid, rejected = [], []
                for entry in entries:
                    ip = ipaddress.ip_address(entry['ip'])
                    if mode_is_active(entry) and (ip.version != 4 or ip not in network or ip == own_ip):
                        rejected.append(entry)
                    else:
                        valid.append(entry)
                apply_all(valid)
                for entry in valid:
                    if entry['apply_state'] != 'applied':
                        mark_applied(entry['ip'], entry['updated_at'], 'applied')
                for entry in rejected:
                    mark_applied(entry['ip'], entry['updated_at'], 'error',
                                 'Source IP is outside current target lab subnet or is the target itself')
                last = signature
                LOG.info('Applied lab policies: %s; rejected %d',
                         [(e['ip'], e['mode']) for e in valid], len(rejected))
            except Exception as exc:
                LOG.exception('Cannot enforce policy')
                for entry in entries:
                    if entry['apply_state'] == 'pending':
                        mark_applied(entry['ip'], entry['updated_at'], 'error', str(exc))
                last = None
        try:
            # Target namespace ONLY, current DROP rules (not packets merely observed by Scapy).
            output = run('-n', '-v', '-x', '-L', CHAIN)
            save_snapshot(output.stdout, policies())
        except Exception as exc:
            LOG.warning('Firewall counter snapshot failed: %s', exc)
        time.sleep(2)


if __name__ == '__main__':
    main()
