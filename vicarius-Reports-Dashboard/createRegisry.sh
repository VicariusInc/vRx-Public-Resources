#!/bin/bash

# Set the current directory's 'certs' subfolder as the data folder for the Docker registry
sudo mkdir -p /var/lib/docker-registry
sudo chown -R root:root /var/lib/docker-registry
sudo chmod -R 755 /var/lib/docker-registry

# Create the Docker registry service
docker service create \
  --name registry \
  --publish published=5000,target=5000 \
  --secret registry-cert \
  --secret registry-key \
  --mount type=bind,source="/var/lib/docker-registry",destination=/var/lib/registry \
  --env REGISTRY_HTTP_TLS_CERTIFICATE=/run/secrets/registry-cert \
  --env REGISTRY_HTTP_TLS_KEY=/run/secrets/registry-key \
  registry:2

if [ $? -ne 0 ]; then
    echo "Failed to create Docker registry service"
    exit 1
fi

echo "Docker registry service created successfully"
