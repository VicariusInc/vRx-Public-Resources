#!/bin/bash

# Update package list
sudo yum update -y
if [ $? -ne 0 ]; then
    echo "Failed to update package list"
    exit 1
fi

# Install necessary dependencies
sudo yum install ca-certificates curl gnupg -y 
if [ $? -ne 0 ]; then
    echo "Failed to install necessary dependencies"
    exit 1
fi

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
if [ $? -ne 0 ]; then
    echo "Failed to add Docker's GPG key"
    exit 1
fi
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the Docker repository to Apt sources
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
if [ $? -ne 0 ]; then
    echo "Failed to add the Docker repository"
    exit 1
fi
# Update package list with Docker packages

# Install Docker Engine, CLI, containerd, and plugins
sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
if [ $? -ne 0 ]; then
    echo "Failed to install Docker components"
    exit 1
fi

sudo systemctl start docker

if ! getent group docker > /dev/null; then
    sudo groupadd docker
    if [ $? -ne 0 ]; then
        echo "Failed to create Docker group"
        exit 1
    fi
fi
# Add the current user to the Docker group
sudo usermod -aG docker $USER
if [ $? -ne 0 ]; then
    echo "Failed to add user to Docker group"
    exit 1
fi

# Initialize Docker Swarm
docker swarm init
if [ $? -ne 0 ]; then
    echo "Failed to initialize Docker Swarm"
    exit 1
fi
# Create a Docker registry service
openssl req -newkey rsa:4096 -nodes -sha256 -x509 -days 365 -out certs/vicarius-vrx-reports.app.crt -keyout certs/vicarius-vrx-reports.app.key -subj "/CN=vicarius-vrx-reports.app"

docker secret create registry-cert certs/vicarius-vrx-reports.app.crt
docker secret create registry-key certs/vicarius-vrx-reports.app.key

mkdir -p /etc/docker/certs.d/vicarius-vrx-reports.app:5000

mkdir /mnt/registry

cp certs/vicarius-vrx-reports.app.crt /etc/docker/certs.d/vicarius-vrx-reports.app:5000/ca.crt
cp certs/vicarius-vrx-reports.app.key /etc/docker/certs.d/vicarius-vrx-reports.app:5000/key.key

sudo systemctl restart docker

#Enable Docker on startup
sudo systemctl enable docker.service
sudo systemctl enable containerd.service

#Docker Registry 

docker service create \
  --name registry \
  --publish published=5000,target=5000 \
  --secret registry-cert \
  --secret registry-key \
  --mount type=bind,source=/mnt/registry,destination=/var/lib/registry \
  --env REGISTRY_HTTP_TLS_CERTIFICATE=/run/secrets/registry-cert \
  --env REGISTRY_HTTP_TLS_KEY=/run/secrets/registry-key \
  registry:2

if [ $? -ne 0 ]; then
    echo "Failed to create Docker registry service"
    exit 1
fi

echo "Docker installation and configuration complete"