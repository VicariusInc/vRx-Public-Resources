#!/bin/bash

sudo docker stack deploy --compose-file webapp/mgntDash/docker-compose.yml vrx-reports-stack
echo "Deployed web management port 8000"
