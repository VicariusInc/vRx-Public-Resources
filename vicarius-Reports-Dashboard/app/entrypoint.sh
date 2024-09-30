#!/bin/sh
# Run your script

# Source and destination file paths
SRC_FILE="/usr/src/app/scripts/state.json"
DEST_FILE="/usr/src/app/reports/state.json"

mkdir -p /usr/src/app/reports

# Check if the destination file does not exist
if [ ! -f "$DEST_FILE" ]; then
    # If it does not exist, copy the source file to the destination
    cp "$SRC_FILE" "$DEST_FILE"
fi

sleep 20

#/usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --allreports  >> /var/log/crontab.log 2>&1
#Initial Pull 
echo "Initial Pull: Starting" 
date
/usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --allreports >> /var/log/initialsync.log 2>&1
#nohup /usr/local/bin/python /usr/src/app/scripts/launcher.py &
echo "Initial Pull: Completed" 
date

# Start cron in foreground
#cron -f
echo "Starting Scheduler"
date
/usr/local/bin/python /usr/src/app/scripts/launcher.py
