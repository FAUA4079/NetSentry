"""Regression tests for server-side filtering of dashboard and observation tables."""
import os
import tempfile
import time
import unittest
from netsentry.rules import Alert
from netsentry.storage import initialize, write_batch, read_dashboard, read_observation, read_suspicious_ips


class TimeFilterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, 'test.db')
        initialize(self.db)
        self.now = time.time()
        self.ip = '172.19.0.3'
        alerts = [
            Alert(self.now - 7200, self.ip, 'PORT_SCAN', 'Old scan', 'High', 'old'),
            Alert(self.now - 120, self.ip, 'PORT_SCAN', 'Recent scan', 'High', 'recent'),
            Alert(self.now - 30, self.ip, 'TRAFFIC_SPIKE', 'Recent spike', 'Medium', 'recent'),
            Alert(self.now - 30, '172.19.0.4', 'PORT_SCAN', 'Other host', 'High', 'other'),
        ]
        pkts = [(self.now - 120, self.ip, '172.19.0.2', 'TCP', 1234, 80, 80, 2, None, None, None, None),
                (self.now - 30, self.ip, '172.19.0.2', 'UDP', 4321, 53, 84, None, None, None, None, None)]
        write_batch({}, alerts, self.db, packet_events=pkts)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dashboard_severity_and_time(self):
        d = read_dashboard(self.db, alert_start=self.now-300, alert_severity='High')
        self.assertEqual(d['filtered_alerts'], 2)
        self.assertEqual(len(d['alerts']), 2)
        self.assertEqual(d['total_alerts'], 4)
        self.assertTrue(all(a['severity'] == 'High' for a in d['alerts']))
        d = read_dashboard(self.db, alert_end=self.now-3600)
        self.assertEqual(d['filtered_alerts'], 1)

    def test_independent_observation_filters(self):
        d = read_observation(self.ip, self.db, alert_start=self.now-300,
                             alert_severity='Medium', packet_start=self.now-60)
        self.assertEqual(d['matching_alerts'], 1)
        self.assertEqual(d['alerts'][0]['rule_id'], 'TRAFFIC_SPIKE')
        self.assertEqual(d['matching_packets'], 1)
        self.assertEqual(d['packets'][0]['protocol'], 'UDP')
        self.assertEqual(d['protocols'], {'UDP': 1})
        self.assertEqual(d['total_alerts'], 3)
        self.assertEqual(d['stored_packet_events'], 2)

    def test_protocol_filter_on_packets(self):
        d = read_observation(self.ip, self.db, packet_protocol='TCP')
        self.assertEqual(d['matching_packets'], 1)
        self.assertEqual(d['packets'][0]['protocol'], 'TCP')
        self.assertEqual(d['protocols'], {'TCP': 1})
        with self.assertRaises(ValueError):
            read_observation(self.ip, self.db, packet_protocol='BAD')

    def test_dashboard_pagination(self):
        first = read_dashboard(self.db, alert_limit=2, alert_offset=0)
        second = read_dashboard(self.db, alert_limit=2, alert_offset=2)
        self.assertEqual(first['filtered_alerts'], 4)
        self.assertEqual(len(first['alerts']), 2)
        self.assertEqual(len(second['alerts']), 2)
        self.assertTrue(set(a['id'] for a in first['alerts']).isdisjoint(
            a['id'] for a in second['alerts']))

    def test_suspicious_ip_summary(self):
        items = read_suspicious_ips(self.db)
        self.assertEqual(len(items), 2)
        host = next(x for x in items if x['source_ip'] == self.ip)
        self.assertEqual(host['alert_count'], 3)
        self.assertEqual(host['rule_id'], 'TRAFFIC_SPIKE')

    def test_no_matches(self):
        d = read_observation(self.ip, self.db, packet_end=self.now-9000)
        self.assertEqual(d['matching_packets'], 0)
        self.assertEqual(d['packets'], [])


if __name__ == '__main__':
    unittest.main()
