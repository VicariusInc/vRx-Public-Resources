#!/bin/bash

sudo docker service rm vrx-reports-stack_app
sudo docker service rm vrx-reports-stack_appdb
sudo docker service rm vrx-reports-stack_metabase
sudo docker service rm vrx-reports-stack_traefik
sudo docker service rm vrx-reports-stack_web