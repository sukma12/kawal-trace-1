from __future__ import annotations
import hashlib, json, os, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from pathlib import Path

# Isolate environment and DB before importing service module.
TEMP = tempfile.TemporaryDirectory()
os.environ['KAWAL_API_DB_PATH'] = str(Path(TEMP.name) / 'test.sqlite3')
os.environ['KAWAL_ADMIN_TOKEN'] = 'f' * 64
os.environ['KAWAL_AUDIT_TOKENS'] = 'cl-test-device-001|' + ('a' * 64)
os.environ['KAWAL_MONITOR_TOKENS'] = 'cl-test-device-001|' + ('b' * 64)
os.environ['KAWAL_INGEST_TOKENS'] = 'ubuntu-test|' + ('c' * 64)
os.environ['KAWAL_RESPONSE_TOKENS'] = 'cl-test-device-001|' + ('d' * 64)
os.environ['KAWAL_RESPONSE_TOTP_SECRETS'] = 'cl-test-device-001|JBSWY3DPEHPK3PXP'
os.environ['KAWAL_WINDOWS_HOST_TOKENS'] = 'win-test-host|' + ('e' * 64)
os.environ['KAWAL_API_ACCEPT_CLIENT_DATA'] = 'true'  # protocol tests need the client-data endpoints; default is off
os.environ['KAWAL_WINDOWS_RESPONSE_ENABLED'] = 'true'
os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = 'true'
os.environ['KAWAL_RESPONSE_ALLOWLIST'] = '1.1.1.1,203.0.113.10'
os.environ['KAWAL_RESPONSE_TOKENS'] = 'cl-test-device-001|' + ('d' * 64)
os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = 'true'
os.environ['KAWAL_RESPONSE_ALLOWLIST'] = '1.1.1.1,203.0.113.10'
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chainlog.e2ee import generate_keypair, encrypt_payload, decrypt_payload
from chainlog.server_archive import ServerArchiveRemoteClient
import server

class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.init_db()
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.APIHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True); cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.httpd.server_address[1]}'
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=2); TEMP.cleanup()

    def request(self, method, path, body=None, token=None, identity=None, identity_header='X-KAWAL-Device-ID', extra=None):
        if body is not None and path.startswith('/api/v1/response-actions') and identity == 'cl-test-device-001' and 'totp_code' not in body:
            body = dict(body)
            body['totp_code'] = server._totp('JBSWY3DPEHPK3PXP')
        if body is not None and path == '/api/v1/windows/response-actions' and identity == 'cl-test-device-001' and 'totp_code' not in body:
            body = dict(body)
            body['totp_code'] = server._totp('JBSWY3DPEHPK3PXP')
        data = None if body is None else json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode()
        headers = {}
        if data is not None: headers['Content-Type'] = 'application/json'
        if token: headers['Authorization'] = 'Bearer ' + token
        if identity: headers[identity_header] = identity
        if extra: headers.update(extra)
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def seed_direct_ssh_failure(self, source_ip):
        now = server.utc_now()
        host_id = 'ubuntu-test'
        event_id = hashlib.sha256(f"seed-ssh-failure-{source_ip}".encode()).hexdigest()
        event = {
            'event_id': event_id, 'timestamp_utc': now, 'host_id': host_id,
            'source': 'linux-journal', 'event_type': 'AUTH_FAILURE',
            'actor': 'test-user', 'source_ip': source_ip,
            'details': {'auth_method': 'ssh', 'service': 'sshd.service', 'reason': 'failed_password'},
        }
        with server.DB_LOCK, server.db_session() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES(?,?,?,?,?)',
                (event_id, host_id, now, server.canonical_json(event), now),
            )

    def build_audit_batch(self):
        device = 'cl-test-device-001'; previous = server.GENESIS; events=[]
        for seq in (1,):
            event = {'seq':seq,'timestamp_utc':'2026-10-21T00:00:00.000Z','event_type':'SYSTEM','actor':'tester','source':'unit-test','details':{'message':'test'},'previous_hash':previous}
            event['record_hash'] = server.audit_record_hash(event)
            event['event_id'] = server.sha256(f"{device}\n{seq}\n{event['record_hash']}")
            event['device_id'] = device
            events.append(event); previous=event['record_hash']
        seed=f"{device}\n1\n1\n{events[0]['record_hash']}\n{events[-1]['record_hash']}"
        batch=server.sha256(seed)
        body={'schema_version':1,'app_version':'1.5.0','device_id':device,'batch_id':batch,'sent_at_utc':'2026-10-21T00:00:00Z','first_seq':1,'last_seq':1,'previous_ack_seq':0,'previous_ack_hash':server.GENESIS,'events':events}
        return body, batch

    def test_health_requires_auth(self):
        self.assertEqual(self.request('GET','/healthz')[0],401)
    def test_health_authenticated(self):
        status,body=self.request('GET','/healthz',token='a'*64,identity='cl-test-device-001')
        self.assertEqual(status,200); self.assertEqual(body['service'],'kawal-trace-api')
    def test_audit_batch_roundtrip_and_idempotent_retry(self):
        body,batch=self.build_audit_batch()
        extra={'Idempotency-Key':batch}
        args=('POST','/api/v1/audit/events:batch',body,'a'*64,'cl-test-device-001','X-KAWAL-Device-ID',extra)
        status,response=self.request(*args)
        self.assertEqual(status,200); self.assertEqual(response['accepted_through_seq'],1)
        status,response=self.request(*args)
        self.assertEqual(status,200); self.assertEqual(response['accepted_through_seq'],1)
    def test_bad_audit_hash_rejected(self):
        body,batch=self.build_audit_batch(); body['events'][0]['record_hash']='f'*64
        # update idempotency header to match altered outer batch; record hash still invalid
        body['batch_id']=server.sha256(f"cl-test-device-001\n1\n1\n{body['events'][0]['record_hash']}\n{body['events'][-1]['record_hash']}")
        status,_=self.request('POST','/api/v1/audit/events:batch',body,'a'*64,'cl-test-device-001',extra={'Idempotency-Key':body['batch_id']})
        self.assertEqual(status,400)
    def test_agent_ingest_dedup_and_feed(self):
        host='ubuntu-test'; eid=hashlib.sha256(b'test-linux-event').hexdigest()
        event={'event_id':eid,'timestamp_utc':'2026-10-21T00:00:00Z','host_id':host,'source':'linux-journal','event_type':'AUTH_FAILURE','actor':'tester','source_ip':'192.0.2.5','details':{'reason':'failed_password','password':'must-not-store'}}
        body={'schema_version':1,'host_id':host,'sent_at_utc':'2026-10-21T00:00:00Z','events':[event]}
        idem=server.sha256(eid)
        for _ in range(2):
            status,response=self.request('POST','/api/v1/security-events:batch',body,'c'*64,host,'X-KAWAL-Host-ID',{'Idempotency-Key':idem})
            self.assertEqual(status,200); self.assertEqual(response['accepted_event_ids'],[eid])
        status,feed=self.request('GET','/api/v1/security-events?limit=100',token='b'*64,identity='cl-test-device-001')
        self.assertEqual(status,200); self.assertTrue(any(x['event_id']==eid for x in feed['events']))
        saved=json.dumps(feed)
        self.assertNotIn('must-not-store',saved)

    def test_archive_events_requires_auth_and_roundtrips_by_date(self):
        status, _ = self.request('POST', '/api/v1/archive/events:batch', {})
        self.assertEqual(status, 401)
        status, _ = self.request('GET', '/api/v1/archive/events/summary?source_profile_id=srv-test-profile-001')
        self.assertEqual(status, 401)
        source_profile = 'srv-test-profile-001'
        event_id = hashlib.sha256(b'archive-event').hexdigest()
        now = '2026-10-22T01:23:45.000Z'
        event = {
            'event_id': event_id, 'timestamp_utc': now, 'host_id': 'remote-linux',
            'source': 'linux-journal', 'event_type': 'AUTH_FAILURE', 'actor': 'test-user',
            'source_ip': '192.0.2.44', 'details': {'reason': 'failed_password', 'service': 'sshd.service'},
        }
        body = {'schema_version': 1, 'source_profile_id': source_profile,
                'source_profile_name': 'Remote lab', 'events': [event]}
        status, response = self.request('POST', '/api/v1/archive/events:batch', body,
                                        'a' * 64, 'cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertEqual(response['accepted_count'], 1)
        # Idempotent retry must not create another row.
        status, response = self.request('POST', '/api/v1/archive/events:batch', body,
                                        'a' * 64, 'cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertEqual(response['accepted_count'], 1)
        status, response = self.request('GET', f'/api/v1/archive/events?source_profile_id={source_profile}&date=2026-10-22',
                                        token='a' * 64, identity='cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertEqual(response['count'], 1)
        self.assertEqual(response['events'][0]['event_id'], event_id)
        status, summary = self.request('GET', f'/api/v1/archive/events/summary?source_profile_id={source_profile}',
                                       token='a' * 64, identity='cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertEqual(summary['total'], 1)
        self.assertEqual(summary['dates'], [{'date': '2026-10-22', 'count': 1}])

    def test_archive_remote_client_roundtrip_and_daily_filter(self):
        client = ServerArchiveRemoteClient(self.base, 'cl-test-device-001', 'a' * 64, allow_remote_storage=True)
        source_profile = 'srv-test-profile-009'
        source_event_id = hashlib.sha256(b'client-source-event').hexdigest()
        event = {
            'event_id': source_event_id, 'timestamp_utc': '2026-10-22T06:07:08.000Z',
            'host_id': 'linux-prod', 'source': 'linux-journal', 'event_type': 'AUTH_FAILURE',
            'actor': 'tester', 'source_ip': '192.0.2.33',
            'details': {'reason': 'failed_password', 'service': 'sshd.service'},
        }
        result = client.upload(source_profile, 'Remote production', [event])
        self.assertEqual(result['accepted_count'], 1)
        result = client.upload(source_profile, 'Remote production', [event])
        self.assertEqual(result['accepted_count'], 1)
        rows = client.fetch_all(source_profile, '2026-10-22')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['event_id'], source_event_id)
        self.assertEqual(rows[0]['host_id'], 'linux-prod')
        self.assertEqual(client.fetch_all(source_profile, '2026-10-21'), [])
        self.assertEqual(client.date_counts(source_profile), [{'date': '2026-10-22', 'count': 1}])

    def test_archive_events_rejects_invalid_event_and_limits_cross_device_access(self):
        source_profile = 'srv-test-profile-002'
        bad = {'schema_version': 1, 'source_profile_id': source_profile, 'events': [{'event_id': 'bad'}]}
        status, body = self.request('POST', '/api/v1/archive/events:batch', bad,
                                    'a' * 64, 'cl-test-device-001')
        self.assertEqual(status, 400)
        status, body = self.request('GET', f'/api/v1/archive/events?source_profile_id={source_profile}',
                                    token='b' * 64, identity='cl-test-device-001')
        self.assertEqual(status, 401)

    def test_response_action_queues_bounded_public_ipv4(self):
        self.seed_direct_ssh_failure('8.8.8.8')
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.8.8', 'ttl_seconds': 300,
                'reason': 'IR ticket test 004', 'confirmation': 'BLOCK 8.8.8.8'}
        status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                        'cl-test-device-001')
        self.assertEqual(status, 202)
        self.assertEqual(response['status'], 'PENDING')
        self.assertEqual(response['source_ip'], '8.8.8.8')
        status, feed = self.request('GET', '/api/v1/response-actions?limit=20', token='b'*64,
                                    identity='cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertTrue(any(a['action_id'] == response['action_id'] and a['status'] == 'PENDING' for a in feed['actions']))

    def test_response_action_rejects_private_and_allowlisted_ips(self):
        for ip in ('127.0.0.1', '1.1.1.1'):
            body = {'action': 'TEMP_BLOCK_IP', 'source_ip': ip, 'ttl_seconds': 300,
                    'reason': 'IR ticket test 005', 'confirmation': f'BLOCK {ip}'}
            status, _ = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                     'cl-test-device-001')
            self.assertIn(status, (400, 403))

    def test_response_action_disabled_by_default_setting(self):
        old = os.environ.get('KAWAL_RESPONSE_ACTIONS_ENABLED', 'false')
        os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = 'false'
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.4.4', 'ttl_seconds': 300,
                'reason': 'IR ticket test 006', 'confirmation': 'BLOCK 8.8.4.4'}
        try:
            status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                            'cl-test-device-001')
            self.assertEqual(status, 403)
            self.assertEqual(response['error'], 'response_actions_disabled')
        finally:
            os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = old

    def test_response_action_rejects_web_event_as_ufw_evidence(self):
        now = server.utc_now()
        source_ip = '8.8.8.4'
        event_id = hashlib.sha256(b'web-auth-event-only').hexdigest()
        event = {
            'event_id': event_id, 'timestamp_utc': now, 'host_id': 'ubuntu-test',
            'source': 'node-web-auth', 'event_type': 'WEB_AUTH_FAILURE',
            'actor': 'unknown', 'source_ip': source_ip,
            'details': {'reason': 'bad_password'},
        }
        with server.DB_LOCK, server.db_session() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO security_events(event_id,host_id,timestamp_utc,payload_json,received_at_utc) VALUES(?,?,?,?,?)',
                (event_id, 'ubuntu-test', now, server.canonical_json(event), now),
            )
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': source_ip, 'ttl_seconds': 300,
                'reason': 'IR ticket test 008', 'confirmation': f'BLOCK {source_ip}'}
        status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                        'cl-test-device-001')
        self.assertEqual(status, 409)
        self.assertEqual(response['error'], 'ip_requires_recent_direct_ssh_failure_from_agent')

    def test_response_action_requires_recent_direct_ssh_failure_event(self):
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.4.4', 'ttl_seconds': 300,
                'reason': 'IR ticket test 007', 'confirmation': 'BLOCK 8.8.4.4'}
        status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                        'cl-test-device-001')
        self.assertEqual(status, 409)
        self.assertEqual(response['error'], 'ip_requires_recent_direct_ssh_failure_from_agent')

    def test_response_action_requires_exact_confirmation_and_reason(self):
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.4.4', 'ttl_seconds': 300,
                'reason': 'no', 'confirmation': 'BLOCK 8.8.4.4'}
        status, _ = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                 'cl-test-device-001')
        self.assertEqual(status, 400)


    def test_response_action_queues_public_ipv4_for_worker(self):
        self.seed_direct_ssh_failure('9.9.9.9')
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '9.9.9.9', 'ttl_seconds': 300,
                'reason': 'IR ticket test 004', 'confirmation': 'BLOCK 9.9.9.9'}
        status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                        'cl-test-device-001')
        self.assertEqual(status, 202)
        self.assertEqual(response['status'], 'PENDING')
        self.assertEqual(response['source_ip'], '9.9.9.9')
        status, feed = self.request('GET', '/api/v1/response-actions?limit=20', token='b'*64,
                                    identity='cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertTrue(any(a['action_id'] == response['action_id'] and a['status'] == 'PENDING' for a in feed['actions']))

    def test_response_action_rejects_private_and_allowlisted_ips(self):
        cases = [('127.0.0.1', 400), ('1.1.1.1', 403)]
        for ip, expected in cases:
            body = {'action': 'TEMP_BLOCK_IP', 'source_ip': ip, 'ttl_seconds': 300,
                    'reason': 'IR ticket test 005', 'confirmation': f'BLOCK {ip}'}
            status, _ = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                     'cl-test-device-001')
            self.assertEqual(status, expected)

    def test_response_action_disabled_by_setting(self):
        os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = 'false'
        try:
            body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.4.4', 'ttl_seconds': 300,
                    'reason': 'IR ticket test 006', 'confirmation': 'BLOCK 8.8.4.4'}
            status, response = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                            'cl-test-device-001')
            self.assertEqual(status, 403)
            self.assertEqual(response['error'], 'response_actions_disabled')
        finally:
            os.environ['KAWAL_RESPONSE_ACTIONS_ENABLED'] = 'true'

    def test_response_action_requires_reason_and_confirmation(self):
        body = {'action': 'TEMP_BLOCK_IP', 'source_ip': '8.8.4.4', 'ttl_seconds': 300,
                'reason': 'no', 'confirmation': 'no'}
        status, _ = self.request('POST', '/api/v1/response-actions', body, 'd'*64,
                                 'cl-test-device-001')
        self.assertEqual(status, 400)


    def test_e2ee_security_event_roundtrip_is_opaque_to_server(self):
        keys = generate_keypair()
        host = 'ubuntu-test'
        event_id = hashlib.sha256(b'e2ee-linux-test').hexdigest()
        timestamp = server.utc_now()
        event = {
            'event_id': event_id, 'timestamp_utc': timestamp, 'host_id': host,
            'source': 'linux-journal', 'event_type': 'AUTH_FAILURE', 'actor': 'test-user',
            'source_ip': '8.8.8.8', 'details': {'auth_method': 'ssh', 'reason': 'failed_password', 'marker_secret': 'should-not-be-readable-by-api'},
        }
        metadata = {
            'event_id': event_id, 'host_id': host, 'timestamp_utc': timestamp, 'stream': 'security',
            'event_type': 'AUTH_FAILURE', 'source': 'linux-journal', 'source_ip': '8.8.8.8', 'auth_method': 'ssh', 'log_name': 'sshd.service',
        }
        envelope = encrypt_payload(keys['public_key_b64'], event, metadata)
        body = {'schema_version': 1, 'host_id': host, 'sent_at_utc': server.utc_now(), 'events': [envelope]}
        status, result = self.request('POST', '/api/v1/encrypted-security-events:batch', body, 'c'*64, host, 'X-KAWAL-Host-ID', {'Idempotency-Key': server.sha256(event_id)})
        self.assertEqual(status, 200); self.assertEqual(result['accepted_event_ids'], [event_id])
        status, feed = self.request('GET', '/api/v1/encrypted-security-events?limit=100', token='b'*64, identity='cl-test-device-001')
        self.assertEqual(status, 200)
        stored = next(item for item in feed['events'] if item['metadata']['event_id'] == event_id)
        self.assertNotIn('should-not-be-readable-by-api', json.dumps(stored))
        self.assertEqual(decrypt_payload(keys['private_key_b64'], stored), event)

    def test_e2ee_audit_batch_roundtrip_and_checkpoint_validation(self):
        keys = generate_keypair()
        device = 'cl-test-device-001'
        timestamp = server.utc_now()
        event = {'seq': 1, 'timestamp_utc': timestamp, 'event_type': 'SYSTEM', 'actor': 'tester', 'source': 'unit-test',
                 'details': {'message': 'private audit body'}, 'previous_hash': server.GENESIS}
        event['record_hash'] = server.audit_record_hash(event)
        event['event_id'] = server.sha256(f"{device}\n1\n{event['record_hash']}")
        event['device_id'] = device
        batch_id = server.sha256(f"{device}\n1\n1\n{event['record_hash']}\n{event['record_hash']}")
        event['batch_id'] = batch_id
        metadata = {'event_id': event['event_id'], 'timestamp_utc': timestamp, 'host_id': device, 'stream': 'audit',
                    'device_id': device, 'seq': 1, 'record_hash': event['record_hash'], 'previous_hash': server.GENESIS, 'batch_id': batch_id}
        envelope = encrypt_payload(keys['public_key_b64'], event, metadata)
        body = {'schema_version': 1, 'app_version': '1.9.0', 'device_id': device, 'batch_id': batch_id,
                'sent_at_utc': timestamp, 'first_seq': 1, 'last_seq': 1, 'previous_ack_seq': 0,
                'previous_ack_hash': server.GENESIS, 'events': [envelope]}
        status, result = self.request('POST', '/api/v1/encrypted-audit/events:batch', body, 'a'*64, device,
                                      'X-KAWAL-Device-ID', {'Idempotency-Key': batch_id})
        self.assertEqual(status, 200); self.assertEqual(result['accepted_through_seq'], 1)
        self.assertNotIn('private audit body', json.dumps(result))
        self.assertEqual(decrypt_payload(keys['private_key_b64'], envelope), event)

    def test_windows_response_action_queue_requires_totp_and_enrolled_host(self):
        body = {'target_host_id': 'win-test-host', 'action': 'WINDOWS_BLOCK_IP',
                'parameters': {'source_ip': '8.8.8.8'}, 'ttl_seconds': 300,
                'reason': 'IR ticket windows-host 014', 'confirmation': 'BLOCK 8.8.8.8'}
        invalid = dict(body, totp_code='000000')
        status, response = self.request('POST', '/api/v1/windows/response-actions', invalid, 'd'*64, 'cl-test-device-001')
        self.assertEqual(status, 403); self.assertEqual(response['error'], 'totp_required_or_invalid')
        status, response = self.request('POST', '/api/v1/windows/response-actions', body, 'd'*64, 'cl-test-device-001')
        self.assertEqual(status, 202); self.assertEqual(response['status'], 'PENDING')
        status, feed = self.request('GET', '/api/v1/windows/response-actions?limit=20', token='b'*64, identity='cl-test-device-001')
        self.assertEqual(status, 200)
        self.assertTrue(any(a['action_id'] == response['action_id'] and a['status'] == 'PENDING' for a in feed['actions']))
        status, pending = self.request('GET', '/api/v1/windows/response-actions?limit=20', token='e'*64, identity='win-test-host', identity_header='X-KAWAL-Host-ID')
        self.assertEqual(status, 200)
        action = next(a for a in pending['actions'] if a['action_id'] == response['action_id'])
        self.assertEqual(action['action'], 'WINDOWS_BLOCK_IP')
        status, result = self.request('POST', '/api/v1/windows/response-actions/' + response['action_id'] + '/result',
                                      {'status': 'SUCCEEDED', 'message': 'test worker result'}, 'e'*64, 'win-test-host', 'X-KAWAL-Host-ID')
        self.assertEqual(status, 200); self.assertEqual(result['status'], 'SUCCEEDED')

    def test_windows_response_action_rejects_unenrolled_host(self):
        body = {'target_host_id': 'win-not-enrolled', 'action': 'WINDOWS_BLOCK_IP',
                'parameters': {'source_ip': '8.8.8.8'}, 'ttl_seconds': 300,
                'reason': 'IR ticket windows-host 015', 'confirmation': 'BLOCK 8.8.8.8'}
        status, response = self.request('POST', '/api/v1/windows/response-actions', body, 'd'*64, 'cl-test-device-001')
        self.assertEqual(status, 403); self.assertEqual(response['error'], 'target_windows_host_not_enrolled')

    def test_bad_feed_token_rejected(self):
        self.assertEqual(self.request('GET','/api/v1/security-events?limit=100',token='x'*64,identity='cl-test-device-001')[0],401)


    def test_membership_enroll_approve_claim_and_revoke(self):
        device_id = 'cl-member-device-0001'
        claim_secret = 'c' * 64
        code, body = self.request('POST', '/api/v1/enrollment/request',
                                  {'device_id': device_id, 'claim_secret': claim_secret,
                                   'display_name': 'Laptop anggota'})
        self.assertEqual(code, 202)
        self.assertEqual(body['status'], 'PENDING')

        code, body = self.request('GET', '/api/v1/admin/members', token='f' * 64)
        self.assertEqual(code, 200)
        self.assertTrue(any(m['device_id'] == device_id and m['status'] == 'PENDING' for m in body['members']))

        code, body = self.request('POST', '/api/v1/admin/members',
                                  {'device_id': device_id, 'display_name': 'Laptop anggota'}, token='f' * 64)
        self.assertEqual(code, 200)
        self.assertEqual(body['status'], 'ACTIVE')

        code, creds = self.request('POST', '/api/v1/enrollment/claim',
                                   {'device_id': device_id, 'claim_secret': claim_secret})
        self.assertEqual(code, 200)
        self.assertEqual(creds['device_id'], device_id)
        self.assertEqual(len(creds['device_token']), 64)
        self.assertEqual(len(creds['monitor_token']), 64)
        self.assertEqual(len(creds['response_token']), 64)
        self.assertTrue(creds['response_totp_secret'])

        code, body = self.request('GET', '/healthz', token=creds['device_token'], identity=device_id)
        self.assertEqual(code, 200)
        code, body = self.request('GET', '/api/v1/security-events', token=creds['monitor_token'], identity=device_id)
        self.assertEqual(code, 200)

        code, body = self.request('DELETE', f'/api/v1/admin/members/{device_id}', token='f' * 64)
        self.assertEqual(code, 200)
        code, body = self.request('GET', '/healthz', token=creds['device_token'], identity=device_id)
        self.assertEqual(code, 401)
        code, body = self.request('POST', '/api/v1/enrollment/claim',
                                  {'device_id': device_id, 'claim_secret': claim_secret})
        self.assertEqual(code, 403)

    def test_membership_admin_requires_admin_token(self):
        code, body = self.request('GET', '/api/v1/admin/members')
        self.assertEqual(code, 401)

    def test_client_data_endpoints_are_off_unless_the_operator_enables_them(self):
        """The app keeps every database on the device, so a default server must not store client logs/archives."""
        gated = [
            ('GET', '/api/v1/archive/events/summary?source_profile_id=srv-test-profile-001', None),
            ('GET', '/api/v1/archive/events?source_profile_id=srv-test-profile-001', None),
            ('POST', '/api/v1/archive/events:batch', {}),
            ('POST', '/api/v1/audit/events:batch', {}),
            ('POST', '/api/v1/encrypted-audit/events:batch', {}),
        ]
        old = os.environ.get('KAWAL_API_ACCEPT_CLIENT_DATA')
        try:
            for value in ('false', ''):
                os.environ['KAWAL_API_ACCEPT_CLIENT_DATA'] = value
                for method, path, body in gated:
                    # Even a fully authorised caller is refused: the switch is about what this server stores.
                    status, response = self.request(method, path, body, token='a' * 64, identity='cl-test-device-001')
                    self.assertEqual(status, 403, (method, path, value))
                    self.assertEqual(response['error'], 'client_data_storage_disabled')
            # Everything that is not client data keeps working with the same credentials.
            status, _ = self.request('GET', '/healthz', token='a' * 64, identity='cl-test-device-001')
            self.assertEqual(status, 200)
        finally:
            if old is None:
                os.environ.pop('KAWAL_API_ACCEPT_CLIENT_DATA', None)
            else:
                os.environ['KAWAL_API_ACCEPT_CLIENT_DATA'] = old

    def test_server_default_for_client_data_is_off(self):
        old = os.environ.pop('KAWAL_API_ACCEPT_CLIENT_DATA', None)
        try:
            self.assertFalse(server.client_data_storage_enabled())
        finally:
            if old is not None:
                os.environ['KAWAL_API_ACCEPT_CLIENT_DATA'] = old

if __name__ == '__main__':
    unittest.main(verbosity=2)
