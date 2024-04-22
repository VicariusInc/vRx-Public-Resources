#!/bin/bash
mkdir -p /mnt/metabase

sudo docker stack deploy --compose-file metabase/docker-compose.yml vrx-reports-stack
echo "Log into http://your_host:4000 to setup metabase account"
