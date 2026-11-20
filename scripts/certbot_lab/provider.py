"""TEST ONLY: scoped fake Cloudflare API and real authoritative DNS.

Runs only in the disposable lab network. Never use as a real DNS/provider server.
The unauthenticated __fixture endpoints are for the test coordinator only.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from urllib.parse import parse_qs, urlsplit
import uuid

from dnslib import A, QTYPE, RCODE, RR, TXT
from dnslib.server import BaseResolver, DNSServer, DNSLogger

lock = threading.RLock()
tokens = json.loads(Path('/fixture/tokens.json').read_text())
records = {}
events = []
mode = 'normal'
target = os.environ.get('TARGET_IP', '127.0.0.1')


class Resolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        name = str(request.q.qname).rstrip('.')
        with lock:
            if mode == 'servfail' and name.startswith('_acme-challenge.'):
                reply.header.rcode = RCODE.SERVFAIL
            elif request.q.qtype == QTYPE.TXT:
                for record in records.values():
                    if record['name'] == name and (mode != 'propagation' or record['id'].startswith('sentinel-')):
                        reply.add_answer(RR(name, QTYPE.TXT, ttl=0, rdata=TXT(record['content'])))
            elif request.q.qtype == QTYPE.A:
                reply.add_answer(RR(name, QTYPE.A, ttl=0, rdata=A(target)))
        return reply


class API(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log authorization headers or credential values.

    def respond(self, status, result=None, code=None):
        payload = {'success': code is None, 'errors': [] if code is None else [{'code': code, 'message': 'fixture access denied'}], 'messages': [], 'result': result}
        if isinstance(result, list):
            payload['result_info'] = {'page': 1, 'per_page': 100, 'count': len(result), 'total_count': len(result), 'total_pages': 1}
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_request(self):
        global mode
        parsed = urlsplit(self.path)
        query = {name: values[0] for name, values in parse_qs(parsed.query).items()}
        count = int(self.headers.get('Content-Length', '0'))
        if count > 16384:
            return self.respond(413, code=1000)
        body = json.loads(self.rfile.read(count)) if count else {}
        with lock:
            if parsed.path == '/__fixture/state':
                return self.respond(200, {'records': list(records.values()), 'events': events, 'mode': mode})
            if parsed.path == '/__fixture/config' and self.command == 'POST':
                mode = body.get('mode', 'normal')
                if mode not in {'normal', 'propagation', 'servfail', 'delete-denied'}:
                    return self.respond(400, code=1000)
                for name in body.get('sentinels') or []:
                    identity = 'sentinel-' + name
                    records[identity] = {'id': identity, 'type': 'TXT', 'name': name, 'content': 'preserve-unrelated-value', 'ttl': 120}
                return self.respond(200, {})
            capability = tokens.get(self.headers.get('Authorization', '').removeprefix('Bearer '))
            if capability is None:
                events.append({'operation': 'denied', 'reason': 'invalid-token'})
                return self.respond(403, code=9109)
            prefix = '/client/v4/zones'
            if parsed.path == prefix and self.command == 'GET':
                events.append({'operation': 'zone-read', 'name': query.get('name')})
                return self.respond(200, [{'id': 'zone-fixture', 'name': 'nexus.test'}] if query.get('name') == 'nexus.test' and capability != 'other-zone' else [])
            prefix += '/zone-fixture/dns_records'
            if parsed.path == prefix and self.command == 'GET':
                result = [record for record in records.values() if all(record.get(key) == value for key, value in query.items() if key in {'type', 'name', 'content'})]
                return self.respond(200, result)
            if capability != 'edit':
                events.append({'operation': 'denied', 'reason': 'scope'})
                return self.respond(403, code=1009)
            if parsed.path == prefix and self.command == 'POST':
                if body.get('type') != 'TXT' or not body.get('name', '').startswith('_acme-challenge.') or not body['name'].endswith('.nexus.test'):
                    return self.respond(403, code=1009)
                record = {**body, 'id': uuid.uuid4().hex}
                records[record['id']] = record
                events.append({'operation': 'create', 'id': record['id'], 'name': record['name']})
                return self.respond(200, record)
            if parsed.path.startswith(prefix + '/') and self.command == 'DELETE':
                identity = parsed.path.rsplit('/', 1)[1]
                if identity.startswith('sentinel-') or mode == 'delete-denied':
                    events.append({'operation': 'delete-denied', 'id': identity})
                    return self.respond(403, code=1009)
                if identity not in records:
                    return self.respond(404, code=81044)
                del records[identity]
                events.append({'operation': 'delete', 'id': identity})
                return self.respond(200, {'id': identity})
            return self.respond(404, code=1000)

    do_GET = handle_request
    do_POST = handle_request
    do_DELETE = handle_request


for tcp in [False, True]:
    DNSServer(Resolver(), port=8053, address='0.0.0.0', tcp=tcp, logger=DNSLogger(log='-request,-reply,-truncated,-error', prefix=False)).start_thread()
ThreadingHTTPServer(('0.0.0.0', 8056), API).serve_forever()
