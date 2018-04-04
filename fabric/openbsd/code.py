from fabric.api import local, run, cd, sudo, settings, put, env

def hello():

    env.shell = '/bin/ksh -c'

    # Karma
    run("su - _karma -c 'cd /opt/karma/karma && git checkout .'")
    run("su - _karma -c 'cd /opt/karma/karma && git pull'")

    # Restart Services
    run('/etc/rc.d/nginx restart')
    run('/etc/rc.d/karma_worker restart')
    run('/etc/rc.d/karma_wsgi restart')

