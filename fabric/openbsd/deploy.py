from fabric.api import local, run, cd, sudo, settings, put, env

def hello():

    env.shell = '/bin/ksh -c'

    # COPY FILES
    put('files/karma_worker', '/etc/rc.d/karma_worker', mode=0755)
    put('files/karma_wsgi', '/etc/rc.d/karma_wsgi', mode=0755)
    put('files/rc.conf.local', '/etc/rc.conf.local')
    put('files/vimrc', '/etc/vimrc')
    put('files/nginx.conf', '/etc/nginx/nginx.conf')
    put('files/ssl/karma.crt', '/etc/nginx/karma.crt')
    put('files/ssl/karma.key', '/etc/nginx/karma.key')
    put('files/id_rsa*', '/opt/karma/.ssh/', mode=0600)
    run('chown _karma:_karma /opt/karma/.ssh/*')

    # Karma
    run("su - _karma -c 'cd karma && git checkout .'")
    run("su - _karma -c 'cd karma && git pull .'")
    run("su - _karma -c 'cd karma && /opt/karma/.venv/bin/pip install -e .'")
    run("su - _karma -c 'cd karma/karma && /opt/karma/.venv/bin/alembic revision --autogenerate'")
    run("su - _karma -c 'cd karma/karma && /opt/karma/.venv/bin/alembic upgrade head'")

    # Restart Services
    run('/etc/rc.d/nginx restart')
    run('/etc/rc.d/karma_worker restart')
    run('/etc/rc.d/karma_wsgi restart')

