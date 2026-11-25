"""Destructive ONLY to a disposable Accounts fixture DB; never point at user data.

Run in an isolated test container with MariaDB CLI and Accounts HTTP server:
  HANDOFF_TEST_SOCKET=/tmp/handoff/mysql.sock python3 t_deps/handoff-integration.py
The fixture client 'iphone' maps browser -> app, terms v2, Google, fixed HTTPS.
Uses real HTTP handlers and InnoDB; seeded identity substitutes for the provider.
"""
import base64, concurrent.futures, hashlib, json, os, secrets, subprocess, time, unittest
import urllib.error, urllib.parse, urllib.request
BASE=os.environ.get('HANDOFF_TEST_ORIGIN','http://127.0.0.1:8082')
SOCKET=os.environ['HANDOFF_TEST_SOCKET']
def sql(s):
 return subprocess.check_output(['mariadb','--no-defaults','--socket='+SOCKET,'-uroot','-N','-B','accounts'],input=s.encode()).decode().strip()
def quoted(v):return "X'"+str(v).encode().hex()+"'"
def request(path,params,authorized=True):
 r=urllib.request.Request(BASE+path,data=urllib.parse.urlencode(params).encode(),headers={'Authorization':'Bearer fixture' if authorized else 'Bearer invalid'})
 try:res=urllib.request.urlopen(r,timeout=30)
 except urllib.error.HTTPError as e:res=e
 b=res.read()
 return res.status,json.loads(b) if res.headers.get_content_type()=='application/json' else {},res.headers
class Handoff(unittest.TestCase):
 def setUp(self):
  self.aid=secrets.randbelow(10**12)+10**12;self.sk=secrets.token_hex(50);self.verifier=secrets.token_urlsafe(32)
  self.when=int(time.time())-120
  self.d={'session_id':str(self.aid),'account_id':str(self.aid),'login_time':self.when,'handoff_request':{'client':'iphone','state':secrets.token_urlsafe(32),'challenge':base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('='),'redirect_uri':'https://login.example.test/account/app/return','expires':time.time()+600,'authentication':{'method':'oauth','provider':'google','login_time':self.when}}}
  sql(f"INSERT INTO account VALUES ({self.aid},0,1,1,2,'Fixture');")
  sql(f"INSERT INTO session VALUES ({quoted(self.sk)},'browser',0,{time.time()+600},{quoted(json.dumps(self.d))});")
 def update(self):sql(f'UPDATE session SET data={quoted(json.dumps(self.d))} WHERE sk={quoted(self.sk)}')
 def issue(self):return request('/session/handoff/issue',{'sk_context':'browser','sk':self.sk})
 def code(self):
  status,body,headers=self.issue();self.assertEqual(status,200,body);self.assertEqual(headers['Cache-Control'],'no-store');return body['code']
 def redeem(self,code,**kw):return request('/session/handoff/redeem',{'sk_context':'browser','client_id':'iphone','code':code,'code_verifier':self.verifier,**kw})
 def test_success_independent_regular_session(self):
  code=self.code();status,result,h=self.redeem(code);self.assertEqual(status,200,result)
  self.assertNotEqual(result['sk'],self.sk);self.assertEqual(h['Cache-Control'],'no-store')
  rows=sql('SELECT data FROM session WHERE sk='+quoted(result['sk']));d=json.loads(rows)
  self.assertEqual(d['account_id'],str(self.aid));self.assertEqual(d['login_time'],self.when)
  self.assertNotEqual(d['session_id'],self.d['session_id']);self.assertNotIn('handoff_request',d)
  self.assertEqual(request('/info',{'sk_context':'app','sk':result['sk']})[1]['account_id'],str(self.aid))
  self.assertEqual(request('/info',{'sk_context':'browser','sk':result['sk']})[1].get('account_id'),None)
  request('/session/delete',{'use_sk':1,'sk_context':'app','sk':result['sk']})
  self.assertEqual(request('/info',{'sk_context':'browser','sk':self.sk})[1]['account_id'],str(self.aid))
 def test_replay(self):
  code=self.code();self.assertEqual(self.redeem(code)[0],200);self.assertEqual(self.redeem(code)[0],400)
 def test_concurrent_redemption(self):
  code=self.code()
  with concurrent.futures.ThreadPoolExecutor(2) as pool:statuses=list(pool.map(lambda _:self.redeem(code)[0],range(2)))
  self.assertEqual(sorted(statuses),[200,400])
 def test_wrong_verifier_does_not_consume(self):
  code=self.code();self.assertEqual(self.redeem(code,code_verifier='x'*43)[0],400);self.assertEqual(self.redeem(code)[0],200)
 def test_wrong_environment(self):
  code=self.code();self.assertEqual(self.redeem(code,sk_context='production')[0],400);self.assertEqual(self.redeem(code,client_id='other')[0],400)
  self.assertEqual(self.redeem(code)[0],200)
 def test_issue_once(self):self.code();self.assertEqual(self.issue()[0],400)
 def test_expired_code(self):
  code=self.code();sql("UPDATE session SET expires=0 WHERE sk_context='app-handoff-v1'");self.assertEqual(self.redeem(code)[0],400)
 def test_source_logout(self):
  code=self.code();request('/session/delete',{'use_sk':1,'sk_context':'browser','sk':self.sk});self.assertEqual(self.redeem(code)[0],400)
 def test_source_expiry(self):
  code=self.code();sql('UPDATE session SET expires=0 WHERE sk='+quoted(self.sk));self.assertEqual(self.redeem(code)[0],400)
 def test_source_identity_changed(self):
  code=self.code();self.d['account_id']='1';self.update();self.assertEqual(self.redeem(code)[0],400)
 def test_source_reauthenticated(self):
  code=self.code();self.d['login_time']+=1;self.update();self.assertEqual(self.redeem(code)[0],400)
 def test_account_disabled_after_issue(self):
  code=self.code();sql(f'UPDATE account SET admin_status=0 WHERE account_id={self.aid}');self.assertEqual(self.redeem(code)[0],400)
 def test_terms_withdrawn_after_issue(self):
  code=self.code();sql(f'UPDATE account SET terms_version=1 WHERE account_id={self.aid}');self.assertEqual(self.redeem(code)[0],400)
 def test_no_terms(self):
  sql(f'UPDATE account SET terms_version=1 WHERE account_id={self.aid}');self.assertEqual(self.issue()[0],400)
 def test_not_authenticated(self):
  del self.d['handoff_request']['authentication'];self.update();self.assertEqual(self.issue()[0],400)
 def test_expired_request(self):
  self.d['handoff_request']['expires']=0;self.update();self.assertEqual(self.issue()[0],400)
 def test_return_uri_changed(self):
  self.d['handoff_request']['redirect_uri']='https://evil.example/return';self.update();self.assertEqual(self.issue()[0],400)
 def test_unregistered_provider(self):
  self.d['handoff_request']['authentication']['provider']='other';self.update();self.assertEqual(self.issue()[0],400)
 def test_handoff_record_not_a_session(self):
  code=self.code();key='h1'+hashlib.sha256(code.encode()).hexdigest()+'0'*34
  self.assertEqual(request('/session/get',{'sk_context':'app-handoff-v1','sk':key})[1].get('account_id'),None)
  self.assertEqual(request('/info',{'sk_context':'app-handoff-v1','sk':key})[1].get('account_id'),None)
 def test_api_key_required(self):
  self.assertEqual(request('/session/handoff/issue',{'sk_context':'browser','sk':self.sk},False)[0],401)
 def test_ordinary_session_unchanged(self):
  status,s,_=request('/session',{'sk_context':'normal'});self.assertEqual(status,200)
  self.assertTrue(s['set_sk']);self.assertEqual(len(s['sk']),100)
  status,r,_=request('/session',{'sk_context':'normal','sk':s['sk']});self.assertEqual(status,200);self.assertEqual(r['sk'],s['sk']);self.assertFalse(r.get('set_sk'))
if __name__=='__main__':unittest.main(verbosity=2)
