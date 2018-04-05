import base64
from pathlib import Path
from pprint import pprint

import requests
from Crypto import Random
from Crypto.Hash import SHA224
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

dotdir = Path.home() / '.asydns'

dotdir.mkdir(exist_ok=True)

pub_file = dotdir / 'rsa.pub'
key_file = dotdir / 'rsa.key'

if not key_file.is_file():

    print('Generating RSA key ...')
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    pub = key.publickey()

    with key_file.open('w') as k:
        k.write(key.exportKey('PEM').decode())

    with pub_file.open('w') as p:
        p.write(pub.exportKey('PEM').decode())


print('Loading RSA key ...')
with key_file.open() as k:
    key = RSA.importKey(k.read())

with pub_file.open() as p:
    pub = RSA.importKey(p.read())

sha224 = SHA224.new(pub.exportKey('DER')).hexdigest()
print('Your name will be {}.a.asymdns.io'.format(sha224))

print('Checking if the name exists ...')
r = requests.get('https://asydns.org:8443/{}'.format(sha224), verify=False)

print(r.status_code)
print(r.content)

j = r.json()


challenge = base64.b64decode(j['challenge'])
signer = PKCS1_v1_5.new(key)
response = signer.sign(SHA224.new(challenge))
response = base64.b64encode(response).decode()

r = requests.post('https://asydns.org:8443/', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response}, verify=False)

print(r.content)
