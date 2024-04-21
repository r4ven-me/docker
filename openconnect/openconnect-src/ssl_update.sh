#!/usr/bin/env bash

set -e

cd /opt/openconnect

docker-compose up certbot

# docker exec openconnect 'kill -HUP "$(pidof ocserv-main)"'
docker exec openconnect 'occtl reload'

docker system prune -af
