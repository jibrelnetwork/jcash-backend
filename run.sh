#!/bin/bash -e

RUNMODE="${1:-app}"

export APP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "${RUNMODE}" = "app" ]; then
    echo "Starting jcash-backend service, version: `cat /app/version.txt` on node `hostname`"
    python jcash/manage.py migrate --noinput
    python jcash/manage.py collectstatic --noinput --verbosity 0
    cat firstrun.py | python jcash/manage.py shell
    uwsgi --yaml /app/uwsgi.yml
elif [ "${RUNMODE}" = "celerybeat" ]; then
    echo "Starting jcash-backend-celery-beat service, version: `cat /app/version.txt` on node `hostname`"
    celery -A jcash beat -l info
elif [ "${RUNMODE}" = "celeryworker" ]; then
    echo "Starting jcash-backend-celery-worker service, version: `cat /app/version.txt` on node `hostname`"
    celery -A jcash worker -l info
else
    echo "Wrong RUNMODE supplied, exiting"
    exit 1
fi
