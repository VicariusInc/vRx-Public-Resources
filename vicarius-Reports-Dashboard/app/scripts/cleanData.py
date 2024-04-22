# %%
import pandas as pd


import os

import os

def remove_all_except():
    directory = '/usr/src/app/reports/'
    files_to_keep = ['.gitignore','EndpointsEventTask.csv', 'EndpointIncidentesVulnerabilities.csv', 'state.json', 'organization-vrx-reports.pbix']
    # List all files in the directory
    all_files = os.listdir(directory)

    # Remove files that are not in the keep_files list
    for file in all_files:
        file_path = os.path.join(directory, file)
        if file not in files_to_keep and os.path.isfile(file_path):
            try:
                os.remove(file_path)
                print(f"Removed: {file_path}")
            except Exception as e:
                print(f"Error removing {file_path}: {e}")

# Example usage




def cleanData():

    chunk_size = 10**6  # Adjust as needed

    # load Vulnerabilties.csv file to dataframe 
    vulnerabilties_df = pd.read_csv('/usr/src/app/reports/Vulnerabilities.csv')
    # delete duplicates rows based on assethas and cve
    vulnerabilties_df.drop_duplicates(subset=['assethash', 'cve'], keep='first', inplace=True)
    vulnerabilties_df.to_csv('/usr/src/app/reports/VulnerabilitiesND.csv', index=False)
    # load EndpointIncidentesVulnerabilities.csv file to dataframe

    chunk_size = 10**6  # Adjust as needed
    
    chunks = pd.read_csv('/usr/src/app/reports/EndpointIncidentesVulnerabilities.csv', iterator=True, chunksize=chunk_size, dtype={'column1': 'int64', 'column2': 'object', 'column3': 'object', 'column4': 'object', 'column5': 'object', 'column6': 'object', 'column7': 'object', 'column8': 'int64', 'column9': 'float64', 'column10': 'float64', 'column11': 'int64', 'column12': 'object', 'column13': 'int64', 'column14': 'int64'})

    events_df = pd.concat(chunks, ignore_index=True)

    events_df.head()

    #load Endpoints.csv file to dataframe
    endpoints_df = pd.read_csv('/usr/src/app/reports/Endpoints.csv')

    # assing to events_df the following column names "assetid", "asset", "cve", "severity", "eventType", "publisher", "apporso", "threatLevelId", "vulV3exploitlevel", "vulv3basescore", "patchId", "vulsummary", "eventcreatedat", "eventupdatedat"
    events_df.columns = ["assetid", "asset", "cve", "severity", "eventType", "publisher", "apporso", "threatLevelId", "vulV3exploitlevel", "vulv3basescore", "patchId", "vulsummary", "eventcreatedat", "eventupdatedat"]

    # create a new events_df_nd dataframe and filter rows that have assetid that are contained in endpoints_df ID column
    events_df_nd = events_df[events_df['assetid'].isin(endpoints_df['assetid'])]
    events_df_nd.drop_duplicates(subset=["assetid", "asset", "cve", "eventType", "publisher", "apporso", "eventcreatedat", "eventupdatedat"], keep='first', inplace=True)

    events_df_nd.to_csv('/usr/src/app/reports/EndpointIncidentesVulnerabilitiesND.csv', index=False)


def getLastIncidentEventVulnerabilities ():
  try :
    chunk_size = 10**6  # Adjust as needed
    chunks = pd.read_csv('/usr/src/app/reports/EndpointIncidentesVulnerabilities.csv', iterator=True, chunksize=chunk_size, dtype={'column1': 'int64', 'column2': 'object', 'column3': 'object', 'column4': 'object', 'column5': 'object', 'column6': 'object', 'column7': 'object', 'column8': 'int64', 'column9': 'float64', 'column10': 'float64', 'column11': 'int64', 'column12': 'object', 'column13': 'int64', 'column14': 'int64'})
    events_df = pd.concat(chunks, ignore_index=True)
      # assing to events_df the following column names "assetid", "asset", "cve", "severity", "eventType", "publisher", "apporso", "threatLevelId", "vulV3exploitlevel", "vulv3basescore", "patchId", "vulsummary", "eventcreatedat", "eventupdatedat"
    events_df.columns = ["assetid", "asset", "cve", "severity", "eventType", "publisher", "apporso", "threatLevelId", "vulV3exploitlevel", "vulv3basescore", "patchId", "vulsummary", "eventcreatedat", "eventupdatedat"]
    return int (events_df['eventcreatedat'].max() * 1000000)

  except:
    return 0
  

def getLastEndpointsEventTask () :
    try :
        chunk_size = 10**6  # Adjust as needed
        chunks = pd.read_csv('/usr/src/app/reports/EndpointsEventTask.csv', iterator=True, chunksize=chunk_size, dtype={'column1': 'int64', 'column2': 'object', 'column3': 'object', 'column4': 'object', 'column5': 'object', 'column6': 'object', 'column7': 'object', 'column8': 'int64', 'column9': 'float64', 'column10': 'float64', 'column11': 'int64', 'column12': 'object', 'column13': 'int64', 'column14': 'int64'})
        tasks_df = pd.concat(chunks, ignore_index=True)
        return int (tasks_df['CreateAt'].max())

    except:
        return 0
