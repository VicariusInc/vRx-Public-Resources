#!/bin/bash


sudo docker stack deploy --compose-file webapp/mgntDash/docker-compose.yml vrx-reports-stack
echo "Deployed Web app to port 8000"

