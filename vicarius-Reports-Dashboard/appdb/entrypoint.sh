#!/bin/bash

# Set the file paths for the Docker secrets
export POSTGRES_DB_FILE=/run/secrets/postgres_db
export POSTGRES_USER_FILE=/run/secrets/postgres_user
export POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password

# Execute the original entrypoint script with PostgreSQL as the argument
exec docker-entrypoint.sh postgres
