import re
import time
from pathlib import Path

from dnslib import QTYPE, RR, A
from dnslib.server import BaseResolver, DNSServer

NAME_VALID_FOR = 3600

datadir = Path('/tmp/asymdns')
datadir.mkdir(exist_ok=True)

regex_sha224 = re.compile('[0-9a-f]{56}')


class AsymResolver(BaseResolver):

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qn = str(qname)

        if regex_sha224.match(qn.split('.')[0]):
            sha224 = qn.split('.')[0]
            ip_file = datadir / sha224

            if ip_file.is_file() and (time.time() - ip_file.stat().st_mtime) < NAME_VALID_FOR:
                with ip_file.open() as ipf:
                    ip = ipf.read()
                    answer = RR(qname, QTYPE.A, rdata=A(ip), ttl=5)
                    reply.add_answer(answer)

        return reply


if __name__ == "__main__":

    resolver = AsymResolver()

    server = DNSServer(
        resolver,
        port=5353,
        address="0.0.0.0"
    )

    server.start_thread()

    while server.isAlive():
        time.sleep(1)

