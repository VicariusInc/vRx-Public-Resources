#!/bin/bash

# Stop Docker service
echo "Stopping Docker service..."
sudo systemctl stop docker

# Uninstall Docker packages
echo "Uninstalling Docker packages..."
sudo apt-get purge -y docker-ce docker-ce-cli containerd.io

# Remove Docker dependencies
echo "Removing Docker dependencies..."
sudo apt-get autoremove -y

# Remove Docker data and configuration files
echo "Removing Docker data and configuration files..."
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd

# Optional: Remove Docker custom network and other configurations
echo "Removing Docker network and other configurations..."
sudo rm -rf /etc/docker

# Remove Docker Volumes 
echo "removing Docker volumes "
sudo rm -rf /mnt/metabase
sudo rm -rf /mnt/registry


# Optional: Remove Docker’s GPG key and repository
echo "Removing Docker’s GPG key and repository..."
sudo rm /etc/apt/sources.list.d/docker.list
sudo rm /usr/share/keyrings/docker-archive-keyring.gpg

# Clean up any remaining Docker files (use with caution)
# echo "Cleaning up remaining Docker files..."
# sudo find / -name '*docker*' -exec rm -rf {} \;

echo "Docker has been completely purged from your system."
