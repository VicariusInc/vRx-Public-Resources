#!/bin/bash

# Set -e to exit the script if any command fails
set -e

# Function to check if a Docker network exists
check_network() {
    docker network ls | grep -w $1 > /dev/null
    return $?
}

# Function to get the type of a Docker network
get_network_type() {
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
#find  ./app/reports/* -type f -not -name '.gitignore' 'state.json' -print0 | xargs -0 rm -rf
find ./app/reports/* -type f \( -not -name '.gitignore' -and -not -name 'state.json' \) -print0 | xargs -0 rm -rf


# Step 4: Handle the database volume
if docker volume ls -q | grep -w vrx-reports-stack_postgres-data > /dev/null; then
    echo "Volume exists. Leaving Volume intact..."
    #docker volume rm vrx-reports-stack_postgres-data
else
    echo "Volume does not exist."
fi
sleep 10

# Step 6: Deploy the Docker stack
echo "Deploying Docker stack..."
docker stack deploy -c docker-compose.yml vrx-reports-stack

echo "Deployment completed."
echo "Downloading the latest data template"
pwd 
URL="https://github.com/VicariusInc/vRx-Public-Resources/releases/latest/download/mb-datatemplate.dump.gz"
OUTPUT_DIR=$(pwd)
wget -O "$OUTPUT_DIR/app/scripts/metabase/mb-datatemplate.dump.gz" "$URL"

sleep 20
container_name=$(docker ps | grep 'vrx-reports-stack_app.1' | awk '{print $NF}')
docker exec -it "$container_name" /usr/local/bin/python  /usr/src/app/scripts/VickyTopiaReportCLI.py --metabaseTempalateReplace
echo "Running data template upgrade" 


bash ./optional-metabaseInstall.sh
