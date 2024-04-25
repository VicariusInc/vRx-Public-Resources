#!/bin/bash

# Set -e to exit the script if any command fails
set -e

# Step 1: Remove the existing Docker stack
echo "Removing existing Docker stack..."
docker stack rm vrx-reports-stack

# Wait until the stack is fully removed
echo "Waiting for the stack to be fully removed..."
sleep 10

# Step 2: Clean up the logs and reports directories
echo "Cleaning up logs and reports..."
rm -rf ./app/logs/*
rm -rf ./app/reports/*

#docker volume rm vicarius-vrx-reports-stack_postgres-data

#if docker volume ls -q | grep -w  vrx-reports-stack_postgres-data > /dev/null; then
#    echo "Volume exists. Deleting volume..."
#    docker volume rm vrx-reports-stack_postgres-data
#else
#    echo "Volume does not exist."
#fi


# Building the db service (if there's a separate Dockerfile)
#echo "Building the db service Docker image..."
#docker build -t vrx-reports-appdb:latest ./appdb

# Step 3: Build Docker images for each service
# Building the app service
#echo "Building the app service Docker image..."
#docker build -t vrx-reports-app:latest ./app

# Building the superset service (if there's a separate Dockerfile)
#echo "Building the superset service Docker image..."
#docker build -t vicarius-vrx-reports-superset:latest ./superset

docker network rm vrx-reports-stack_vicarius-network
docker network create vrx-reports-stack_vicarius-network

# Step 4: Deploy the Docker stack
echo "Deploying Docker stack..."
docker stack deploy -c docker-compose.yml vrx-reports-stack

#cd superset
#docker compose up

echo "Deployment completed."
