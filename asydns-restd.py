import base64
import json
import re
import sys
from pathlib import Path
from pprint import pprint
from time import time

import falcon
from Crypto import Random
from Crypto.Hash import SHA224
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

dotdir = Path.home() / '.asydns'
dotdir.mkdir(exist_ok=True)

cfg_file = dotdir / 'config.json'

pub_file = dotdir / 'server.pub'
key_file = dotdir / 'server.key'

datadir = dotdir / 'data'
datadir.mkdir(exist_ok=True)

regex_sha224 = re.compile('[0-9a-f]{56}')

defaults = {
    'domain': 'a.asydns.com',
    'ttl' : 3600,
}

cfg = defaults

if cfg_file.is_file():
    try:
        with cfg_file.open() as c:
            cfg.update(json.loads(c.read()))
    except Exception:
        print('error loading config file, using defaults', file=sys.stderr)


if not key_file.is_file():

    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    pub = key.publickey()

    with key_file.open('w') as k:
        k.write(key.exportKey('PEM').decode())

    with pub_file.open('w') as p:
        p.write(pub.exportKey('PEM').decode())


with key_file.open() as k:
    key = RSA.importKey(k.read())

with pub_file.open() as p:
    pub = RSA.importKey(p.read())


class AsymDNS(object):

    def on_head(self, req, resp, sha224=''):
        """Handles HEAD requests"""

        if not regex_sha224.match(sha224):
            resp.status = falcon.HTTP_400
            resp.body = ('\nInvalid sha 224.\n\n')
            return False

        ip_file = datadir / (sha224)

        if not ip_file.is_file() or (time() - ip_file.stat().st_mtime) > cfg['ttl']:
            resp.status = falcon.HTTP_404
        else:
            resp.status = falcon.HTTP_200

        return True


    def on_get(self, req, resp, sha224=''):
        """Handles GET requests"""

        token = '{}@{}@{}'.format(
            req.remote_addr,
            int(time()),
            SHA224.new(Random.new().read(64)).hexdigest(),
        )

        challenge = pub.encrypt(token.encode(), '0')[0]
        challenge = base64.b64encode(challenge).decode()

        if not regex_sha224.match(sha224):
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Invalid SHA224'})
            return False

        ip_file = datadir / sha224

        ip = None
        if not ip_file.is_file() or (time() - ip_file.stat().st_mtime) > cfg['ttl']:
            resp.status = falcon.HTTP_404
        else:
            resp.status = falcon.HTTP_200
            with ip_file.open() as ipf:
                ip = ipf.read()

        resp.body = json.dumps({
            'ip': ip,
            'challenge' : challenge,
        })


    def on_post(self, req, resp):
        """Handles POST requests"""

        body = req.stream.read()
        data = json.loads(body.decode('utf-8'))

        try:
            client_pub = RSA.importKey(data['pub'])
        except:
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Invalid public key'})
            return False

        try:
            response = base64.b64decode(data['response'])
            challenge = base64.b64decode(data['challenge'])
            decrypted_challenge = key.decrypt(challenge).decode()
            challenge_addr, challenge_time, junk = decrypted_challenge.split('@', maxsplit=2)
            delta = int(challenge_time) - time()
        except:
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Invalid request'})
            return False

        h = SHA224.new(challenge)
        verifier = PKCS1_v1_5.new(client_pub)

        if not verifier.verify(h, response):
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Invalid signature'})
            return False

        if challenge_addr != req.remote_addr:
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Invalid response'})
            return False

        if delta > 30:
            resp.status = falcon.HTTP_400
            resp.body = json.dumps({'error': 'Expired response'})
            return False

        client_sha224 = SHA224.new(client_pub.exportKey(format='DER')).hexdigest()
        ip_file = datadir / client_sha224

        with ip_file.open('w') as ipf:
            ipf.write(req.remote_addr)

        resp.status = falcon.HTTP_200
        resp.body = json.dumps({
            'ip': req.remote_addr,
            'name': '{}.{}'.format(client_sha224, cfg['domain'])
        })

        return True


app = falcon.API()

asymdns = AsymDNS()

app.add_route('/', asymdns)
app.add_route('/{sha224}', asymdns)
