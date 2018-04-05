import base64
import json
from pathlib import Path

import click
import requests
from Crypto import Random
from Crypto.Hash import SHA224
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


@click.command()
@click.option('-u', 'url', default='https://asydns.org', help='API URL')
@click.option('-g', 'generate', is_flag=True, default=False, help='Force the generation of a new key pair')
@click.option('-r', 'revoke', is_flag=True, default=False, help='Revoke the public key')
def cmd_asydns(url, generate, revoke):

    dotdir = Path.home() / '.asydns'

    dotdir.mkdir(exist_ok=True)

    pub_file = dotdir / 'rsa.pub'
    key_file = dotdir / 'rsa.key'


    if generate or not key_file.is_file():

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


    r = requests.get(url + '/api')

    if r.status_code != 200:
        print('Error')
        print(r.content.decode())
        return False

    j = r.json()

    challenge = base64.b64decode(j['challenge'])
    signer = PKCS1_v1_5.new(key)
    response = signer.sign(SHA224.new(challenge))
    response = base64.b64encode(response).decode()

    if revoke:
        r = requests.delete(url + '/api', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response})
    else:
        r = requests.post(url + '/api', json={'pub': pub.exportKey('PEM').decode(), 'challenge' : j['challenge'], 'response': response})

    if r.status_code != 200:
        print('Error')
        print(r.content.decode())
        return False

    print(json.dumps(r.json(), indent=4))

    return True

if __name__ == '__main__':
    cmd_asydns()
