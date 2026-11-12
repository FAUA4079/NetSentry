import unittest
from netsentry.rules import PacketRecord, RuleEngine


def packet(t, port, src='172.20.0.5', syn=True):
    return PacketRecord(t, src, '172.20.0.2', 'TCP', port, syn)


class RulesTest(unittest.TestCase):
    def test_scan_alert_and_cooldown(self):
        eng = RuleEngine(scan_ports=3, prohibited_ports=())
        results = [eng.process(packet(i, 100 + i)) for i in range(6)]
        self.assertEqual(sum(a.rule_id == 'PORT_SCAN' for r in results for a in r), 1)

    def test_repeated_port_not_scan(self):
        eng = RuleEngine(scan_ports=3, prohibited_ports=())
        self.assertFalse(any(eng.process(packet(i, 80)) for i in range(10)))

    def test_window_expiry(self):
        eng = RuleEngine(scan_ports=3, scan_window=5, prohibited_ports=())
        self.assertFalse(eng.process(packet(0, 100)))
        self.assertFalse(eng.process(packet(7, 101)))
        self.assertFalse(eng.process(packet(8, 102)))

    def test_traffic_spike(self):
        eng = RuleEngine(rate_packets=3, prohibited_ports=(), scan_ports=100)
        alerts = sum((eng.process(PacketRecord(i, 'a', 'b', 'UDP')) for i in range(4)), [])
        self.assertEqual([a.rule_id for a in alerts], ['TRAFFIC_SPIKE'])

    def test_restricted_port_is_attempt_not_success(self):
        eng = RuleEngine(prohibited_ports=(22,))
        alerts = eng.process(packet(1, 22))
        self.assertEqual(alerts[0].rule_id, 'RESTRICTED_PORT')
        self.assertIn('not confirmed', alerts[0].details)

    def test_non_syn_not_scan(self):
        eng = RuleEngine(scan_ports=2, prohibited_ports=())
        self.assertFalse(eng.process(packet(1, 70, syn=False)))
        self.assertFalse(eng.process(packet(2, 71, syn=False)))


if __name__ == '__main__':
    unittest.main()
