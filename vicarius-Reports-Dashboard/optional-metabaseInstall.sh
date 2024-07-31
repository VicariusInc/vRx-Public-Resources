#!/bin/bash
mkdir -p /mnt/metabase

sudo docker stack deploy --compose-file metabase/docker-compose.yml vrx-reports-stack
echo "Deployed Metabase"
sudo docker stack deploy --compose-file traefik/docker-compose.yml vrx-reports-stack
echo "Deployed Traefik"
