import os
import tempfile
import time
import unittest
from unittest.mock import patch
from netsentry.storage import initialize, connect
from netsentry.investigation import (risk_assessment,create_incident,update_incident,list_incidents,traffic_analysis)

class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=os.path.join(self.tmp.name,'lab.db')
        initialize(self.db)
        self.now=time.time()
        with connect(self.db) as c:
            c.execute('INSERT INTO alerts(timestamp,source_ip,rule_id,activity,severity,details) VALUES(?,?,?,?,?,?)',(self.now-10,'172.19.0.3','PORT_SCAN','scan','High','10 ports'))
            c.execute('INSERT INTO alerts(timestamp,source_ip,rule_id,activity,severity,details) VALUES(?,?,?,?,?,?)',(self.now-5,'172.19.0.3','UDP_BURST','burst','Medium','80 packets'))
            c.execute('INSERT INTO packet_events(ts,src,dst,protocol,sport,dport,size) VALUES(?,?,?,?,?,?,?)',(self.now-5,'172.19.0.3','172.19.0.2','TCP',40000,80,60))
    def tearDown(self):self.tmp.cleanup()
    def test_risk_reproducible_and_explained(self):
        a=risk_assessment('172.19.0.3',self.db,self.now)
        self.assertEqual(a['count'],2)
        self.assertEqual(a['unique_rules'],2)
        self.assertEqual(a['score'],27)
        self.assertEqual(sum(x['points'] for x in a['factors']),a['score'])
    def test_no_alert_risk(self):
        self.assertEqual(risk_assessment('172.19.0.8',self.db,self.now)['score'],0)
    def test_incident_lifecycle_and_audit(self):
        new=create_incident('172.19.0.3','Review scan','Analyst A','Observed multiple port probes',self.db)
        self.assertEqual(new['status'],'open')
        update_incident('172.19.0.3',new['id'],'Analyst B','investigating','Reviewing evidence',self.db)
        update_incident('172.19.0.3',new['id'],'Analyst B','resolved','No further suspicious activity',self.db)
        cases=list_incidents('172.19.0.3',self.db)
        self.assertEqual(cases['incidents'][0]['status'],'resolved')
        self.assertEqual(len(cases['events']),3)
    def test_reject_non_alerting_ip(self):
        with self.assertRaises(ValueError):create_incident('172.19.0.8','Fake','A','Note',self.db)
    def test_reject_cross_ip_updates(self):
        new=create_incident('172.19.0.3','Case','A','Note',self.db)
        with self.assertRaises(ValueError):update_incident('172.19.0.9',new['id'],'A','resolved','Note',self.db)
    def test_traffic_aggregates(self):
        with patch('netsentry.investigation.time.time',return_value=self.now):
            result=traffic_analysis('172.19.0.3',self.db)
        self.assertEqual(result['ports'][0]['dport'],80)
        self.assertEqual(result['protocols'][0]['protocol'],'TCP')
    def test_invalid_inputs(self):
        with self.assertRaises(ValueError): risk_assessment('not an ip',self.db)
        with self.assertRaises(ValueError):create_incident('172.19.0.3','', 'A','note',self.db)
        new=create_incident('172.19.0.3','Case','A','Note',self.db)
        with self.assertRaises(ValueError):update_incident('172.19.0.3',new['id'],'A','closed','note',self.db)

if __name__=='__main__':unittest.main()
