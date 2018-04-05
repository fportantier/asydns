import base64
from pathlib import Path
from pprint import pprint
import json
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

#sha224 = SHA224.new(pub.exportKey('DER')).hexdigest()
#print('Your name will be {}.a.asymdns.io'.format(sha224))

URL = 'https://asydns.org'
#print('Checking if the name exists ...')
#r = requests.get('https://asydns.org')
r = requests.get(URL + '/api')

#print(r.status_code)
print(r.content)
#print(json.dumps(r.json(), indent=4))

j = r.json()



challenge = base64.b64decode(j['challenge'])
signer = PKCS1_v1_5.new(key)
response = signer.sign(SHA224.new(challenge))
response = base64.b64encode(response).decode()

r = requests.post(URL + '/api', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response})
print(r.content)
print(json.dumps(r.json(), indent=4))

r = requests.delete(URL + '/api', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response})
print(r.content)
print(json.dumps(r.json(), indent=4))

r = requests.post(URL + '/api', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response})
print(r.content)
print(json.dumps(r.json(), indent=4))
