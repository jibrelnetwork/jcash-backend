# jcash
jcash(Jibrel jCash backend)


"Authorization: Token {token}". To get token use: `POST /auth/login/`

# Quick Start

## With docker-compose

First of all - get [Docker-Compose](https://docs.docker.com/compose/install/). Then:

- just start all components with one command:
    ```
    docker-compose pull && docker-compose up
    ```
- build on your computer and start:
    ```
    docker-compose up --build
    ```    

# Installation

## Install system packages

```sh
sudo apt-get update
sudo apt-get install gcc build-essential autoconf libtool pkg-config libssl-dev libffi-dev python3-dev virtualenv
sudo apt-get install git nginx
sudo apt-get install postgresql postgresql-contrib
```


## Install RabbitMQ (Celery`s dependency)

https://linoxide.com/ubuntu-how-to/install-setup-rabbitmq-ubuntu-16-04/
```sh
sudo apt-get update
sudo apt-get install rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server
sudo systemctl status rabbitmq-server
sudo rabbitmqctl add_user rabbituser rabbitpassword
sudo rabbitmqctl add_vhost rabbitvhost
sudo rabbitmqctl set_permissions -p rabbitvhost rabbituser ".*" ".*" ".*"
```


## Set up database

```
sudo -u postgres psql
postgres=# CREATE DATABASE mysaleuser;
postgres=# CREATE USER mysaleuser WITH PASSWORD 'password';
postgres=# ALTER ROLE mysaleuser SET client_encoding TO 'utf8';
postgres=# ALTER ROLE mysaleuser SET default_transaction_isolation TO 'read committed';
postgres=# ALTER ROLE mysaleuser SET timezone TO 'UTC';
postgres=# GRANT ALL PRIVILEGES ON DATABASE mysaledb TO mysaleuser;
postgres=# \q
```


## Clone project and create workdir

```
cd /home/jibrelnetwork
git clone https://github.com/jibrelnetwork/jibrel-jcash-backend
cd jibrel-jcash-backend
```


## Create python virtual environment

```sh
virtualenv -p /usr/bin/python3.6 venv
source venv/bin/activate
```


## Install packages

```sh
pip install -r requirements.txt
pip install --editable ./
```


## Configure

Check settings `./jcash/settings.py`
You can create dotenv file `./jcash/.env` and put all env vars here

## Init database

```sh
python jcash/dj-manage.py migrate
```


## Launching Django server in dev mode

```sh
python jcash/dj-manage.py runserver
```


## Deploying (Gunicorn)

### Testing Gunicorn's Ability to Serve the Project

```sh
cd ~/jcash
source venv/bin/activate
gunicorn --bind 0.0.0.0:8000 -w 4 jcash.wsgi
```

### Create a Gunicorn systemd Service File

```sh
sudo nano /etc/systemd/system/jcash.service
```

```
[Unit]
Description=jcash daemon
After=network.target

[Service]
User=jibrelnetwork
Group=www-data
WorkingDirectory=/home/jibrelnetwork/jibrel-jcash-backend/
ExecStart=/home/jibrelnetwork/jibrel-jcash-backend/venv/bin/gunicorn --access-logfile - --workers 4 --bind unix:/home/jibrelnetwork/jibrel-jcash-backend/jcash.sock jcash.wsgi:application

[Install]
WantedBy=multi-user.target
```

Commands

```
sudo systemctl start jcash
sudo systemctl restart jcash
sudo systemctl stop jcash
```

### Check response of web server

```
curl -H "Content-Type: application/json" -X POST -d '{"email":"test1@local","password":"password"}' http://localhost:8080/auth/login/
```

# Launch celery tasks

```
mkdir -p ./celery-sys/
mkdir -p ./celery-log/

source venv/bin/activate

celery -A jcash worker \
    --pidfile="./celery-sys/%n.pid" \
    --logfile="./celery-log/%n-%i.log" \
    --loglevel=INFO
```
