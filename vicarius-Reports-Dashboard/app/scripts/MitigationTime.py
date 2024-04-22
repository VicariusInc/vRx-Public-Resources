# Description: This script calculates the mitigation time for each mitigated vulnerability event, from EndPointIncidentesVulnerabilities.csv report.

import pandas as pd
# load csv file to dataframe
# Comma-separated string of new column names


def get_mitigation_time():
        events_report_path = f'/usr/src/app/reports/EndpointIncidentesVulnerabilitiesND.csv'
        mitigation_report_path = f'/usr/src/app/reports/MitigationTime.csv'
        head = "assetid,asset,cve,severity,eventType,publisher,apporso,threatLevelId,vulV3exploitlevel,vulv3basescore,patchId,vulsummary,eventcreatedat,eventupdatedat"
        df = pd.read_csv(events_report_path, encoding='utf-8')
        # Split the comma-separated string into a list
        new_columns_list = head.split(',')

        # Remove leading/trailing whitespaces from column names
        new_columns_list = [col.strip() for col in new_columns_list]

        # Assign the new column names to the dataframe
        #df.columns = new_columns_list
   
        # Filter the dataframe to only include the columns we want
        mitigated_events = df[df['eventType'] == 'MitigatedVulnerability']
        detected_events = df[df['eventType'] == 'DetectedVulnerability']
        mitigated_events.rename(columns={'eventcreatedat': 'mitigation_date'}, inplace=True)
        merged_mitigated = pd.merge(mitigated_events, detected_events[['assetid', 'cve', 'eventcreatedat']], on=['assetid', 'cve'], how='inner', suffixes=('_mitigated', '_detected'))
        merged_mitigated.rename(columns={'eventcreatedat': 'detection_date'}, inplace=True)
        merged_mitigated['mitigation_time'] = (merged_mitigated['mitigation_date'] - merged_mitigated['detection_date']) / 1000 / 3600 / 24
        merged_mitigated['mitigation_time'] = merged_mitigated['mitigation_time'].dropna().astype(float)
        merged_mitigated = merged_mitigated[merged_mitigated.mitigation_time != ""]

        merged_mitigated.to_csv(mitigation_report_path, index=False)



