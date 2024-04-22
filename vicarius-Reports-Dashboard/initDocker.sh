#!/bin/bash

# Function to create or update a docker secret
create_or_update_secret() {
    secret_name=$1
    secret_value=$2

    # Check if the secret already exists
    if docker secret ls | grep -q $secret_name; then
        # Secret exists, so remove it first
        docker secret rm $secret_name
    fi

    # Create the secret with the new value
    echo "$secret_value" | docker secret create $secret_name -
}

# Prompt for API key
read -sp "Enter your API key: " api_key
echo
create_or_update_secret api_key "$api_key"

# Prompt for Dashboard ID
read -p "Enter your Dashboard ID (e.g., organization in https://organization.vicarius.cloud/): " dashboard_id
create_or_update_secret dashboard_id "$dashboard_id"

# Prompt for PostgreSQL database name
create_or_update_secret postgres_db "$dashboard_id"

# Prompt for PostgreSQL username
read -p "Enter your PostgreSQL username: " postgres_user
create_or_update_secret postgres_user "$postgres_user"

# Prompt for PostgreSQL password
read -sp "Enter your PostgreSQL password: " postgres_password
echo
create_or_update_secret postgres_password "$postgres_password"

echo "Docker secrets created successfully."

read -p "List Optional tools to install (e.g., metabase)" optional_tools
echo 
create_or_update_secret optional_tools "$optional_tools"
