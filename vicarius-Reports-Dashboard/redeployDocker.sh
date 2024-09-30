#!/bin/bash

# Set -e to exit the script if any command fails
set -e

# Function to check if a Docker network exists
check_network() {
    echo "Check network function"
    docker network ls | grep -w $1 > /dev/null
    return $?
}

# Function to get the type of a Docker network
get_network_type() {
    echo "Get network function"
    docker network inspect --format '{{ .Scope }}' $1 2> /dev/null || echo "none"
}

# Network name
NETWORK_NAME="vrx-reports-stack_vicarius-network"

# Step 1: Remove the existing Docker stack if it exists
echo "Checking if Docker stack exists..."
if docker stack ls | grep -q "vrx-reports-stack"; then
    echo "Removing existing Docker stack..."
    docker stack rm vrx-reports-stack

    # Wait until the stack is fully removed
    echo "Waiting for the stack to be fully removed..."
    sleep 10
else
    echo "No existing stack found. Skipping removal."
fi

# Step 2: Clean up the logs and reports directories
echo "Cleaning up logs and reports..."
find  ./app/reports/* -type f -not -name '.gitignore' -print0 | xargs -0 rm -rf


# Step 4: Handle the database volume
if docker volume ls -q | grep -w vrx-reports-stack_postgres-data > /dev/null; then
    echo "Volume exists. Deleting volume..."
    docker volume rm vrx-reports-stack_postgres-data
else
    echo "Volume does not exist."
fi


# Step 6: Deploy the Docker stack
echo "Deploying Docker stack..."
docker stack deploy -c docker-compose.yml vrx-reports-stack

echo "Deployment completed."

# Step 7: check for a successful first run 

#echo "The first run must complete before deploying any optional tools"
#echo "depending on the amount of data this can take some time" 
##LOG_FILE="app/logs/crontab.log"
#LINE_TO_CHECK="End of Run "
#i=0
#echo "Checking App first run"
#while IFS= read -r line; do
#  echo "Still running ..." 
#  sleep 120
#  if [[ "$line" == *"$LINE_TO_CHECK"* ]]; then
#    echo "Found the line: $LINE_TO_CHECK"
#    exit 0
#  fi
#done < "$LOG_FILE"

#echo "Run Completed" 

