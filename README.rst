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
