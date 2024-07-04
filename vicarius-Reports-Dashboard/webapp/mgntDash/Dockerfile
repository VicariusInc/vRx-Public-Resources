# Use the official Python image from the Docker Hub
FROM python:3.12.2-bookworm

# Set the working directory
WORKDIR /usr/src/app

# Copy the requirements file
ADD ./requirements.txt /usr/src/app/requirements.txt
#COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update
RUN apt-get install lsb-release
RUN sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
RUN apt-get update
RUN apt-get -y install postgresql-client-16
# Copy the entire project
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
