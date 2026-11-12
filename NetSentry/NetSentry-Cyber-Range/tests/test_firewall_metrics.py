import unittest
from netsentry.firewall_metrics import parse_drop_rules

class TestFirewallMetrics(unittest.TestCase):
    def test_extract_drop_only(self):
        sample = '''Chain NETSENTRY (1 references)
 pkts bytes target prot opt in out source destination
 482 23786 DROP all -- * * 172.20.0.4 0.0.0.0/0
  15   750 RETURN all -- * * 172.20.0.7 0.0.0.0/0
  12   600 DROP all -- * * 172.20.0.7 0.0.0.0/0
'''
        self.assertEqual(parse_drop_rules(sample),{'172.20.0.4':(482,23786),'172.20.0.7':(12,600)})
    def test_ignore_unrelated_or_malformed(self):
        self.assertEqual(parse_drop_rules('DROP garbage\n0 0 ACCEPT all -- * * 1.2.3.4 0.0.0.0/0'),{})

if __name__=='__main__':unittest.main()
