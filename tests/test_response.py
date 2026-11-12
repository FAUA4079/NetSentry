import os
import tempfile
import unittest
from netsentry.storage import initialize
from netsentry.response import request_action, policies, audit, mark_applied

class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name,'test.sqlite')
        initialize(self.db)
    def tearDown(self):
        self.tmp.cleanup()
    def test_observe_block_release_audit(self):
        self.assertEqual(request_action('172.19.0.3','observe','investigating',db_path=self.db)['mode'],'observe')
        request_action('172.19.0.3','blocked','confirmed misuse',db_path=self.db)
        self.assertEqual(policies(self.db)[0]['mode'],'blocked')
        request_action('172.19.0.3','released','safe after review',db_path=self.db)
        self.assertEqual(policies(self.db)[0]['mode'],'released')
        self.assertEqual(len(audit(self.db)),3)
    def test_reject_invalid_ip_and_release_unmanaged(self):
        with self.assertRaises(ValueError):request_action('1.2.3.4;rm -rf /','blocked','test',db_path=self.db)
        with self.assertRaises(ValueError):request_action('172.19.0.4','released','test',db_path=self.db)
    def test_applied_marker_and_repeat(self):
        request_action('172.19.0.5','observe','test',db_path=self.db)
        item=policies(self.db)[0]
        mark_applied(item['ip'],item['updated_at'],'applied',db_path=self.db)
        self.assertEqual(policies(self.db)[0]['apply_state'],'applied')
        with self.assertRaises(ValueError):request_action('172.19.0.5','observe','again',db_path=self.db)

if __name__=='__main__':unittest.main()
