import logging
import subprocess
import time
from threading import Lock
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import gc 


# Configure logging to log to a file
logging.basicConfig(
    filename='/var/log/scheduler_log.log',  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log format
    datefmt='%Y-%m-%d %H:%M:%S'    # Date format for log entries
)

logger = logging.getLogger(__name__)

# Create a global lock to ensure only one job runs at a time
job_lock = Lock()

# Define the jobs to run external Python scripts
def run_script(script_path):
    try:
        logger.info(f"Starting execution of {script_path}")
        subprocess.run(['python3', script_path], check=True)
        logger.info(f"Successfully executed {script_path} at: {datetime.now()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing {script_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        logger.info(f"Finished execution of {script_path}")
    gc.collect()

def run_bash_script(script_path):
    try:
        logger.info(f"Starting execution of {script_path} " + str(datetime.now()))
        # Run the external bash script using subprocess
        subprocess.run(['bash', script_path], check=True)
        logger.info(f"Successfully executed {script_path} at: {datetime.now()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing {script_path}: {e} "  + str(datetime.now()))
    except Exception as e:
        logger.error(f"Unexpected error: {e} "  + str(datetime.now()))
    finally:
        logger.info(f"Finished execution of {script_path} "  + str(datetime.now()))
# Job 1: Run a specific Python script
def job1():
    with job_lock:
        print("launcing job 1" + str(datetime.now()))
        script_path = "/usr/src/app/scripts/refreshTables.sh"  # Update with your script's path
  # Update with your script's path
        run_bash_script(script_path)
        print("sleeping" + str(datetime.now()))
# Job 2: Run another Python script
def job2():
    with job_lock:
        print("launcing job 2 " + str(datetime.now()))
        script_path = "/usr/src/app/scripts/activeVulnsSync.sh"  # Update with your script's path
        run_bash_script(script_path)
        print("sleeping" + str(datetime.now()))
# Job 3: Run another Python script
def job3():
    with job_lock:
        print("launcing job 3" + str(datetime.now()))
        script_path = "/usr/src/app/scripts/difTables.sh"  # Update with your script's path
        run_bash_script(script_path)
        print("sleeping" + str(datetime.now()))

# Create a scheduler
scheduler = BackgroundScheduler()

# Add jobs to the scheduler
scheduler.add_job(job1, trigger=IntervalTrigger(hours=4))  # Runs every 10 seconds
scheduler.add_job(job2, trigger=IntervalTrigger(hours=4))   # Runs every 1 minute
scheduler.add_job(job3, trigger=IntervalTrigger(hours=4))   # Runs every 1 minute
# Start the scheduler
print("starting Scheduler: " + str(datetime.now()))
scheduler.start()
logger.info("Scheduler started" +  str(datetime.now()))

try:
    # Keep the script running
    while True:
        print("Running Script: " +  str(datetime.now()))
        logger.info("Running Script:" +  str(datetime.now()))
        gc.collect()
        time.sleep(3600)
        
except (KeyboardInterrupt, SystemExit):
    # Shut down the scheduler when exiting
    scheduler.shutdown()
    print("Scheduler shut down: " +  str(datetime.now()))
    logger.info("Scheduler shut down" +  str(datetime.now()))
