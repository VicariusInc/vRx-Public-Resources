FROM python:3.12.2-bookworm

WORKDIR /usr/src/app

# Copy only the requirements.txt initially
ADD ./requirements.txt /usr/src/app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y cron
RUN apt-get install lsb-release
RUN sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
RUN apt-get update
RUN apt-get -y install postgresql-client-16

COPY . .

# Schedule your script using cron
#COPY crontab /etc/cron.d/my-crontab
#RUN chmod 0644 /etc/cron.d/my-crontab
#RUN crontab /etc/cron.d/my-crontab
#COPY initcron /etc/cron.d/initcron
#RUN chmod 0644 /etc/cron.d/initcron
#RUN crontab /etc/cron.d/initcron



COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
