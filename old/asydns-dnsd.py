import json
import os
import pwd
import re
import sys
import time
from pathlib import Path

from dnslib import QTYPE, RR, A
from dnslib.server import BaseResolver, DNSServer


def drop_privileges(new_user):
    if os.getuid() != 0:
        return

    pwnam = pwd.getpwnam(new_user)

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(pwnam.pw_gid)
    os.setuid(pwnam.pw_uid)

    #Ensure a reasonable umask
    old_umask = os.umask(0o22)

    return True


class AsymResolver(BaseResolver):

    def __init__(self):

        user = pwd.getpwnam(sys.argv[1])

        self.homedir = Path(user.pw_dir)
        self.dotdir = self.homedir / '.asydns'
        self.datadir = self.dotdir / 'data'

        self.datadir.mkdir(parents=True, exist_ok=True)

        self.regex_sha224 = re.compile('[0-9a-f]{56}')

        self.cfg_file = self.dotdir / 'config.json'

        defaults = {
            'domain': 'a.asydns.org',
            'ttl' : 3600,
            'registers': {}
        }

        self.cfg = defaults

        if self.cfg_file.is_file():
            try:
                with self.cfg_file.open() as c:
                    self.cfg.update(json.loads(c.read()))
            except Exception:
                print('error loading config file, using defaults', file=sys.stderr)


    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qn = str(qname)

        print(request.q)

        if qname in self.cfg['registers'].keys():
            answer = RR(qname, QTYPE.A, rdata=A(registers[qname]), ttl=300)
            reply.add_answer(answer)

        if self.regex_sha224.match(qn.split('.')[0]):
            sha224 = qn.split('.')[0]
            ip_file = self.datadir / sha224

            if ip_file.is_file() and (time.time() - ip_file.stat().st_mtime) < self.cfg['ttl']:
                with ip_file.open() as ipf:
                    ip = ipf.read()
                    answer = RR(qname, QTYPE.A, rdata=A(ip), ttl=30)
                    reply.add_answer(answer)

        return reply


if __name__ == "__main__":

    resolver = AsymResolver()

    server = DNSServer(
        resolver,
        port=53,
        address="0.0.0.0"
    )

    server.start_thread()
    drop_privileges(sys.argv[1])

    while server.isAlive():
        time.sleep(1)
