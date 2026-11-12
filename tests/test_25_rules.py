"""Exercise every new detection rule using synthetic target-inbound packet metadata."""
import unittest
from dataclasses import replace
from netsentry.rules import PacketRecord, RuleEngine, ALL_RULES
from netsentry.config import load_ruleset


BASE = PacketRecord(100, '172.19.0.10', '172.19.0.2', 'TCP', 80)


class RuleCoverageTests(unittest.TestCase):
    def engine(self, rule, threshold=None):
        e = RuleEngine(enabled={rule}, cooldown=0)
        if threshold is not None:
            e.thresholds[rule] = threshold
        return e

    def assert_fires(self, rule, records, threshold=None):
        e = self.engine(rule, threshold)
        alerts = [a for p in records for a in e.process(p)]
        self.assertTrue(any(a.rule_id == rule for a in alerts), rule)
        self.assertTrue(all(a.rule_id == rule for a in alerts))

    def test_all_25_registered(self):
        self.assertEqual(len(ALL_RULES), 25)
        self.assertEqual(set(load_ruleset('config/rules.json')['enabled']), set(ALL_RULES))

    def test_udp_port_scan(self):
        self.assert_fires('UDP_PORT_SCAN', [replace(BASE, protocol='UDP', dport=100+i, ts=100+i) for i in range(3)], (3,15))

    def test_udp_burst(self):
        self.assert_fires('UDP_BURST', [replace(BASE, protocol='UDP', ts=100+i) for i in range(3)], (3,10))

    def test_tcp_rst_burst(self):
        self.assert_fires('TCP_RST_BURST', [replace(BASE, tcp_flags=4,ts=100+i) for i in range(3)], (3,10))

    def test_tcp_fin_scan(self):
        self.assert_fires('TCP_FIN_SCAN',[replace(BASE,tcp_flags=1)])

    def test_tcp_null_scan(self):
        self.assert_fires('TCP_NULL_SCAN',[replace(BASE,tcp_flags=0)])

    def test_tcp_xmas_scan(self):
        self.assert_fires('TCP_XMAS_SCAN',[replace(BASE,tcp_flags=0x29)])

    def test_tcp_ack_probe(self):
        self.assert_fires('TCP_ACK_PROBE',[replace(BASE,tcp_flags=0x10,size=40,dport=i,ts=100+i) for i in range(3)],(3,15))

    def test_ip_fragment(self):
        self.assert_fires('IP_FRAGMENT',[replace(BASE,fragmented=True)])

    def test_icmp_large_echo(self):
        self.assert_fires('ICMP_LARGE_ECHO',[replace(BASE,protocol='ICMP',icmp_echo_request=True,size=1300)])

    def test_icmp_unreach_burst(self):
        self.assert_fires('ICMP_UNREACH_BURST',[replace(BASE,protocol='ICMP',icmp_type=3,ts=100+i) for i in range(3)],(3,10))

    def test_dns_query_burst(self):
        self.assert_fires('DNS_QUERY_BURST',[replace(BASE,protocol='UDP',dns_qname='test.example.',ts=100+i) for i in range(3)],(3,10))

    def test_dns_long_query(self):
        self.assert_fires('DNS_LONG_QUERY',[replace(BASE,protocol='UDP',dns_qname='x'*95+'.example.')])

    def test_dns_entropy(self):
        self.assert_fires('DNS_HIGH_ENTROPY_LABEL',[replace(BASE,protocol='UDP',dns_qname='a9b8c7d6e5f4g3h2i1j0.example.')])

    def test_dns_txt_burst(self):
        self.assert_fires('DNS_TXT_BURST',[replace(BASE,protocol='UDP',dns_qname='test.example.',dns_qtype=16,ts=100+i) for i in range(3)],(3,10))

    def test_dns_unique_names(self):
        self.assert_fires('DNS_UNIQUE_NAME_BURST',[replace(BASE,protocol='UDP',dns_qname=f'{i}.example.',ts=100+i) for i in range(3)],(3,15))

    def test_dns_nxdomain(self):
        self.assert_fires('DNS_NXDOMAIN_BURST',[replace(BASE,protocol='UDP',dns_is_response=True,dns_rcode=3,ts=100+i) for i in range(3)],(3,10))

    def test_http_sensitive_path(self):
        self.assert_fires('HTTP_SENSITIVE_PATH',[replace(BASE,http_method='GET',http_path='/.env')])

    def test_http_uncommon_method(self):
        self.assert_fires('HTTP_UNCOMMON_METHOD',[replace(BASE,http_method='TRACE',http_path='/')])

    def test_http_long_uri(self):
        self.assert_fires('HTTP_LONG_URI',[replace(BASE,http_method='GET',http_path='/'+'x'*600)])

    def test_http_scanner_ua(self):
        self.assert_fires('HTTP_SCANNER_USER_AGENT',[replace(BASE,http_method='GET',http_path='/',http_user_agent='sqlmap/1.8')])

    def test_negative_http_normal(self):
        e=RuleEngine(enabled={'HTTP_SENSITIVE_PATH','HTTP_UNCOMMON_METHOD','HTTP_LONG_URI','HTTP_SCANNER_USER_AGENT'})
        self.assertEqual(e.process(replace(BASE,http_method='GET',http_path='/index.html',http_user_agent='Mozilla/5.0')),[])

    def test_negative_dns_response_not_query(self):
        e=RuleEngine(enabled={'DNS_LONG_QUERY','DNS_QUERY_BURST'},thresholds={'DNS_LONG_QUERY':(10,0),'DNS_QUERY_BURST':(1,10)})
        self.assertEqual(e.process(replace(BASE,protocol='UDP',dns_is_response=True,dns_qname='longlong.example.')),[])

    def test_window_expires(self):
        e=self.engine('UDP_BURST',(3,2))
        self.assertEqual([a for t in (100,104,108) for a in e.process(replace(BASE,protocol='UDP',ts=t))],[])


if __name__=='__main__':
    unittest.main()
