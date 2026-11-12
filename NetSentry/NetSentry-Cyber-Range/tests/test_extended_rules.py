import unittest
from netsentry.rules import PacketRecord, RuleEngine


class ExtendedRulesTests(unittest.TestCase):
    def test_syn_burst(self):
        e = RuleEngine(scan_ports=1000, rate_packets=1000, syn_packets=3, prohibited_ports=())
        a = sum((e.process(PacketRecord(i, 'a', 'b', 'TCP', 80, True)) for i in range(3)), [])
        self.assertEqual([x.rule_id for x in a], ['SYN_BURST'])

    def test_icmp_flood(self):
        e = RuleEngine(rate_packets=1000, icmp_packets=3)
        a = sum((e.process(PacketRecord(i, 'a', 'b', 'ICMP', icmp_echo_request=True)) for i in range(3)), [])
        self.assertEqual([x.rule_id for x in a], ['ICMP_ECHO_FLOOD'])

    def test_disabled_rules(self):
        e = RuleEngine(rate_packets=2, scan_ports=2, prohibited_ports=(22,), enabled=[])
        self.assertEqual(e.process(PacketRecord(1, 'a', 'b', 'TCP', 22, True)), [])
        self.assertEqual(e.process(PacketRecord(2, 'a', 'b', 'TCP', 23, True)), [])

    def test_icmp_echo_reply_not_detected(self):
        e = RuleEngine(rate_packets=1000, icmp_packets=2)
        for i in range(10):
            self.assertEqual(e.process(PacketRecord(i, 'a', 'b', 'ICMP', icmp_echo_request=False)), [])
