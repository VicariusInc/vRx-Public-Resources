
import datetime

def timestamptodatetime(timestamp_with_ms):

    timestamp, ms = divmod(timestamp_with_ms, 1000)
    dt = datetime.datetime.fromtimestamp(timestamp) + datetime.timedelta(milliseconds=ms)    
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
  
    return formatted_time