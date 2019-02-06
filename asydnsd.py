import base64
import json
import os
import pwd
import re
import sys
from pathlib import Path
from time import time
import logging

import falcon
from Crypto import Random
from Crypto.Hash import SHA224
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from backend.route53 import Route53Backend


backend_mapping = {
    'Route53' : Route53Backend,
}


class AsyDNS():

    def __init__(self):

        user = pwd.getpwuid(os.getuid())

        self.home_dir = Path(user.pw_dir)

        self.code_dir = Path(__file__).parent

        dotdir = self.home_dir / '.asydns'
        dotdir.mkdir(exist_ok=True)

        config_file = dotdir / 'config.json'

        pub_file = dotdir / 'server.pub'
        key_file = dotdir / 'server.key'

        self.logger = logging.getLogger('asydnsd')
        self.logger.setLevel(logging.DEBUG)

        #self.datadir = dotdir / 'data'
        #self.datadir.mkdir(exist_ok=True)

        #self.revokedir = dotdir / 'revoked'
        #self.revokedir.mkdir(exist_ok=True)

        self.regex_sha224 = re.compile('[0-9a-f]{56}')

        if not config_file.is_file():
            raise Exception('NoConfigFile', 'No config file. Please, create it in: {}'.format(str(config_file)))

        try:
            with config_file.open() as c:
                self.config = json.loads(c.read())
        except Exception:
            raise Exception('InvalidConfigFile', 'Error loading config file. Please, provide a valid JSON')

        backend_class = backend_mapping.get(self.config['backend'], None)
        self.backend = backend_class(self.config)

        if not self.backend:
            raise Exception('NoBackend', 'Please, define a backend. Options: {}'.format(','.join(backend_mapping.keys())))

        if not key_file.is_file():

            random_generator = Random.new().read
            key = RSA.generate(2048, random_generator)
            pub = key.publickey()

            with key_file.open('w') as k:
                k.write(key.exportKey('PEM').decode())

            with pub_file.open('w') as p:
                p.write(pub.exportKey('PEM').decode())


        with key_file.open() as k:
            self.key = RSA.importKey(k.read())

        with pub_file.open() as p:
            self.pub = RSA.importKey(p.read())


    def _validate_response(self, req):

        try:
            body = req.stream.read()
            data = json.loads(body.decode('utf-8'))
            challenge = base64.b64decode(data['challenge'])
            response = base64.b64decode(data['response'])
            client_pub = RSA.importKey(data['pub'])
            decrypted_challenge = self.key.decrypt(challenge).decode()
            challenge_addr, challenge_time, junk = decrypted_challenge.split('@', maxsplit=2)
            delta = int(challenge_time) - time()
        except Exception as e:
            self.logger.error(e)
            return { 'status': falcon.HTTP_400, 'error': 'Invalid request' }

        h = SHA224.new(challenge)
        verifier = PKCS1_v1_5.new(client_pub)

        if not verifier.verify(h, response):
            return { 'status': falcon.HTTP_400, 'error': 'Invalid signature' }

        if challenge_addr != req.remote_addr:
            return { 'status': falcon.HTTP_400, 'error': 'Invalid response' }

        if delta > 30:
            return { 'status': falcon.HTTP_400, 'error': 'Expired response' }

        sha224 = SHA224.new(client_pub.exportKey(format='DER')).hexdigest()

        return {
            'status': falcon.HTTP_200,
            'sha224' : sha224,
            'error': None,
        }


    def on_get(self, req, resp):
        """Handles GET requests"""

        token = '{}@{}@{}'.format(
            req.remote_addr,
            int(time()),
            SHA224.new(Random.new().read(64)).hexdigest(),
        )

        challenge = self.pub.encrypt(token.encode(), '0')[0]
        challenge = base64.b64encode(challenge).decode()

        resp.body = json.dumps({
            'challenge' : challenge,
        })


    def on_post(self, req, resp):
        """Handles POST requests"""

        validation = self._validate_response(req)

        if validation['status'] != falcon.HTTP_200:
            resp.status = validation['status']
            resp.body = json.dumps({ 'error' : validation['error'] })
            return

        current = self.backend.check(validation['sha224'])

        if current['status'] == 'revoked':
            resp.status = falcon.HTTP_200
            resp.body = json.dumps({
                'error': 'revoked public key',
                'name': '{}.{}'.format(validation['sha224'], self.config['domain'])
            })
            return True

        try:
            self.backend.update(validation['sha224'], req.remote_addr)
            resp.status = falcon.HTTP_200
            resp.body = json.dumps({
                'ip': req.remote_addr,
                'name': '{}.{}'.format(validation['sha224'], self.config['domain'])
            })
        except Exception as e:
            self.logger.error(e)
            resp.status = falcon.HTTP_503
            resp.body = json.dumps({
                'error' : 'An error has been ocurred',
            })

        return True


    def on_delete(self, req, resp):
        """Handles DELETE requests"""

        validation = self._validate_response(req)

        if validation['status'] != falcon.HTTP_200:
            resp.status = validation['status']
            resp.body = json.dumps({ 'error' : validation['error'] })
            return

        try:
            self.backend.revoke(validation['sha224'])
            resp.status = falcon.HTTP_200
            resp.body = json.dumps({
                'message' : '{}.{} has been revoked'.format(validation['sha224'], self.config['domain']),
            })
        except Exception as e:
            self.logger.error(e)
            resp.status = falcon.HTTP_503
            resp.body = json.dumps({
                'error' : 'An error has been ocurred',
            })

        return True


app = falcon.API()
app.req_options.auto_parse_form_urlencoded = True

asydns = AsyDNS()

app.add_route('/api', asydns)
