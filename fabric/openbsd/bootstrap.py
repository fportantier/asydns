from pathlib import Path
from fabric.api import local, run, cd, sudo, settings, put, env

env.shell = '/bin/ksh -c'

home_dir = '/opt/asydns/'
venv_dir = home_dir + 'venv/'
bin_dir = venv_dir + 'bin/'
pip3 = bin_dir + 'pip3'
py3 = bin_dir + 'python3.6'


def update():

    with cd(home_dir):
        run("git reset --hard HEAD")
        run("git pull")

    run('chown -R _asydns:_asydns /opt/asydns')

    run('rcctl restart asydns_restd')
    run('rcctl restart asydns_dnsd')


def deploy():

    packages = [
        'git',
        'python%3.6',
        'vim--no_x11',
    ]

    run('echo https://ftp4.usa.openbsd.org/pub/OpenBSD > /etc/installurl')
    run('pkg_add -x {}'.format(' '.join(packages))) # -x don't show progress

    with settings(warn_only=True):
        run('useradd -d /opt/asydns -s /bin/ksh -L daemon _asydns')

    with settings(warn_only=True):
        if run("test -d %s" % home_dir).failed:
            run("git clone -q https://github.com/portantier/asydns.git %s" % home_dir)
    with cd(home_dir):
        run("git pull")

    run('chown -R _asydns:_asydns /opt/asydns')

    with settings(warn_only=True):
        if run("test -d %s" % home_dir + 'venv').failed:
            run("su - _asydns -c 'python3.6 -m venv %'" % venv_dir)

    with cd(home_dir + 'venv'):
        run("su - _asydns -c '{} install --upgrade pip'".format(pip3))
        run("su - _asydns -c '{} install -r requirements.txt'".format(pip3))

    put('files/asydns_restd', '/etc/rc.d/asydns_restd', mode='0744')
    put('files/asydns_dnsd', '/etc/rc.d/asydns_dnsd', mode='0744')
    put('files/rc.conf.local', '/etc/rc.conf.local')
    put('files/acme-client.conf', '/etc/acme-client.conf')

    put('files/httpd.conf', '/etc/rc.d/httpd.conf')
    run('rcctl restart httpd')

    with settings(warn_only=True):
        run('acme-client -vAD asydns.org')

    run("chmod a+r /etc/ssl/asydns.org.key")

    # SERVICE RESTART
    run('rcctl restart asydns_restd')
    run('rcctl restart asydns_dnsd')

