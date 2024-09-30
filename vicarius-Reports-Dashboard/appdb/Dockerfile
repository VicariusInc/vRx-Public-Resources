FROM postgres:16.0

# Copy the custom entrypoint script
COPY entrypoint.sh /usr/local/bin/

# Make sure the script is executable
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set the custom script as the entrypoint
ENTRYPOINT ["entrypoint.sh"]
