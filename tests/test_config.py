import json
import tempfile
import unittest
from pathlib import Path
from netsentry.config import load_ruleset


class ConfigTests(unittest.TestCase):
    def test_default_rules(self):
        rules = load_ruleset('config/rules.json')
        self.assertEqual(rules['scan_ports'], 10)
        self.assertIn('ICMP_ECHO_FLOOD', rules['enabled'])

    def test_invalid_threshold_rejected(self):
        rules = json.loads(Path('config/rules.json').read_text())
        rules['settings']['scan_ports'] = -1
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            path.write_text(json.dumps(rules))
            with self.assertRaises(ValueError):
                load_ruleset(path)

    def test_unrecognized_rule_rejected(self):
        rules = json.loads(Path('config/rules.json').read_text())
        rules['enabled'].append('RUN_COMMAND')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            path.write_text(json.dumps(rules))
            with self.assertRaises(ValueError):
                load_ruleset(path)
