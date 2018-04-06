AsyDNS (Asymmetric DNS)
-----------------------

My task in this world is provide DNS names to all the people that has an Asymmetric Cryptography Key Pair

I can give you awesome names like:

e6e9b4c019af6b1787780b2d25a94c1e960760474ce5544499efcff9.a.asydns.org

Ok, maybe not an "awesome name", but a really dynamic name.

What do you need?

1. Generate a public/private key pair
2. Claim your asydns.org subdomain
3. Probe (cryptographically) that you have the private key of the key pair
4. Done! You have an AsyDNS subdomain!  :)

The API it's really simple, and a Python 3.x client it's included with the package, just:

.. code-block:: bash

    $ python3 asydns-client.py

The client generates a new RSA key pair, and claims your new domain name.

By default, we use asydns.org, but you can host your own AsyDNS server with your own domain.

How to use
==========

If you simply want a domain name, you can use the asydns-bash client, that only needs bash, curl and
openssl.

https://github.com/portantier/asydns-bash

Also, a reference implementation resides in this repo, at asydns-client.py

Video
=====

https://www.youtube.com/watch?v=zdZfc7E1VIc

Technical Details
=================

The AsyDNS protocol it's really simple, but you need some cryptography background to understand it:

First, you need to have an RSA key pair. This will be used to sign your requests.

Second, you need to make an HTTP GET request to the AsyDNS server (default: https://asydns.org).

You will receive a challenge, that you need to sign with your private key.

Third, you need to make an HTTP POST request to the AsyDNS server, with the following:

    - The challenge that you've received on the GET request
    - The signed challenge (that you've signed with your private key)
    - Your public key

If the signature can be verified, the AsyDNS will create/update a record that will be:

${SHA224_OF_YOUR_PUBLIC_KEY}.a.asydns.org

That record will point to your public IP address.

Now, you can query that registry using the DNS protocol, like this:

.. code-block:: bash

    $ dig +short 6a3d1cf600b9dbb4c37db687d4bc3d731a0fe1a31ac14b9a3dceb49b.a.asydns.org
    184.31.49.214

Also, you can revoke the registry (you need the private key to do that).

The process to revoke a registry it's equal to the process described to create a record, 
with only one modification: instead of a POST request, you need to make a DELETE HTTP request.

When a registry it's revoked, never will be valid. But, you can simply create a new RSA key 
pair and request another registry.

