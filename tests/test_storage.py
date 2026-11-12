import os
import tempfile
import unittest
from netsentry.rules import Alert
from netsentry.storage import initialize, write_batch, read_dashboard


class StorageTest(unittest.TestCase):
    def test_aggregate_and_alert(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, 'test.db')
            initialize(db)
            write_batch({(2000000000, 'TCP'): 3},
                        [Alert(2000000000, '10.0.0.1', 'PORT_SCAN', 'Possible scan', 'High', 'test')], db)
            # Old buckets are cleaned based on wall-clock time; year 2033 is safe for this demo.
            stats = read_dashboard(db)
            self.assertEqual(stats['total_packets'], 3)
            self.assertEqual(stats['total_alerts'], 1)
            self.assertEqual(stats['alerts'][0]['source_ip'], '10.0.0.1')


if __name__ == '__main__':
    unittest.main()
