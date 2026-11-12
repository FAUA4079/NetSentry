"""Tests for bounded per-IP observation evidence and response context."""
import os
import tempfile
import time
import unittest
from netsentry.rules import Alert
from netsentry.storage import initialize, write_batch, read_observation
from netsentry.response import request_action


class ObservationTest(unittest.TestCase):
    def test_source_specific_logs_and_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            db = os.path.join(folder, 'test.db')
            initialize(db)
            now = time.time()
            packet = (now, '172.19.0.3', '172.19.0.2', 'TCP', 50555, 80,
                      60, 2, None, '', 'GET', '/index.html')
            write_batch({}, [Alert(now, '172.19.0.3', 'PORT_SCAN', 'Scan', 'High', '10 ports'),
                             Alert(now, '172.19.0.4', 'PORT_SCAN', 'Scan', 'High', '10 ports')],
                        db, packet_events=[packet])
            request_action('172.19.0.3', 'observe', 'Review traffic', db_path=db)
            result = read_observation('172.19.0.3', db)
            self.assertEqual(result['total_alerts'], 1)
            self.assertEqual(result['stored_packet_events'], 1)
            self.assertEqual(result['alerts'][0]['source_ip'], '172.19.0.3')
            self.assertEqual(result['packets'][0]['http_path'], '/index.html')
            self.assertEqual(result['protocols'], {'TCP': 1})
            self.assertEqual(result['policy']['mode'], 'observe')
            self.assertEqual(result['audit'][0]['reason'], 'Review traffic')
            self.assertEqual(read_observation('172.19.0.4', db)['stored_packet_events'], 0)

    def test_bad_ip(self):
        with self.assertRaises(ValueError):
            read_observation('not-an-ip')


if __name__ == '__main__':
    unittest.main()
