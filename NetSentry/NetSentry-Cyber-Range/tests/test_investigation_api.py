import os
import tempfile
import time
import unittest
from unittest.mock import patch
try:
    from netsentry import dashboard
except ModuleNotFoundError as error:
    if error.name != "flask":
        raise
    dashboard = None
from netsentry.storage import initialize, connect

@unittest.skipUnless(dashboard is not None, "Flask must be installed for API integration tests")
class InvestigationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=os.path.join(self.tmp.name,'test.db')
        initialize(self.db)
        with connect(self.db) as db:
            db.execute('INSERT INTO alerts(timestamp,source_ip,rule_id,activity,severity,details) VALUES(?,?,?,?,?,?)',(time.time(),'172.19.0.3','PORT_SCAN','scan','High','10 ports'))
        self.patch1=patch('netsentry.storage.DB',self.db)
        self.patch2=patch('netsentry.investigation.connect',lambda db_path=None:connect(db_path or self.db))
        self.patch1.start();self.patch2.start()
        self.client=dashboard.app.test_client()
    def tearDown(self):self.patch2.stop();self.patch1.stop();self.tmp.cleanup()
    def test_read_api(self):
        response=self.client.get('/api/investigate/172.19.0.3')
        self.assertEqual(response.status_code,200)
        self.assertIn('risk',response.json)
    def test_reject_cross_origin(self):
        response=self.client.post('/api/investigate/172.19.0.3/incidents',json={'title':'Case','actor':'Analyst','note':'Reason'})
        self.assertEqual(response.status_code,403)
    def test_create_and_update(self):
        headers={'Origin':'http://localhost','X-NetSentry-Action':'human-review'}
        created=self.client.post('/api/investigate/172.19.0.3/incidents',json={'title':'Case','actor':'Analyst','note':'Reason'},headers=headers)
        self.assertEqual(created.status_code,201,created.json)
        id_=created.json['id']
        updated=self.client.post(f'/api/investigate/172.19.0.3/incidents/{id_}',json={'actor':'Analyst','status':'resolved','note':'Investigated'},headers=headers)
        self.assertEqual(updated.status_code,200,updated.json)
        result=self.client.get('/api/investigate/172.19.0.3').json
        self.assertEqual(result['incidents'][0]['status'],'resolved')
        self.assertEqual(len(result['events']),2)

if __name__=='__main__':unittest.main()
