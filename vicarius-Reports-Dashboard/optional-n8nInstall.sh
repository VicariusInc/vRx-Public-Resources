#!/bin/bash
mkdir /mnt/n8n

sudo docker stack deploy --compose-file n8n/docker-compose.yml vrx-reports-stack
echo "Log into https://your_host:5678 to setup n8n account"
