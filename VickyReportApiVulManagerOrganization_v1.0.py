#Author: Joaldir Rani

from datetime import datetime
import requests
import json
import datetime
import sys
import time

apikey = ''
urldashboard = ''

f = open('VickyReportApiVulManagerOrganization_v1.0.csv', 'a', encoding='UTF8')

f.write('Asset,PathOrProduct,PathOrProductDesc,Severity,CVE,Summary,link,CreateAt,UpdateAt\n')

def getCountTasksEvents(apikey,urldashboard):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def timestamptodatetime(timestamp_with_ms):

    timestamp, ms = divmod(timestamp_with_ms, 1000)
    dt = datetime.datetime.fromtimestamp(timestamp) + datetime.timedelta(milliseconds=ms)    
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
  
    return formatted_time

def getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,count):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort' : 'organizationEndpointVulnerabilitiesEndpoint.endpointName',
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
    parsed = json.loads(response.text)


    for i in parsed['serverResponseObject']:

        #print(json.dumps(i, indent=4, sort_keys=True))
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        vulid = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId']
        #https://www.vicarius.io/research-center/vulnerability/CVE-2020-8927-id263765
        link = 'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + str(vulid)
        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
        except:
            productName = ""

        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        sensitivityLevelName = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        
        vulnerabilitySummary = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySummary'] 
        vulnerabilitySummary = str(vulnerabilitySummary).replace("\"","'")
        
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        try:
            createAt = timestamptodatetime(i['organizationEndpointVulnerabilitiesCreatedAt'])
            updateAt = timestamptodatetime(i['organizationEndpointVulnerabilitiesUpdatedAt'])
        except:
            createAt = ""
            updateAt = ""

        productName = productName.replace(',',"")
        productRawEntryName = productRawEntryName.replace(',',"")
        vulnerabilitySummary = vulnerabilitySummary.replace("\r","").replace("\n",">>")
        vulnerabilitySummary = vulnerabilitySummary.replace(',',"")

        f.write(asset + "," + productName + "," + productRawEntryName + "," + sensitivityLevelName + "," + cve + ",\"" + vulnerabilitySummary + "\"," + link + "," + createAt + "," + updateAt + "\n")
                
    fr0m = fr0m + siz3

    if fr0m < count:
        time.sleep(3)
        getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,count)
    else:
        print("Done!!")
        f.close()
        sys.exit()
    
fr0m = 308959
siz3 = 50
count = getCountTasksEvents(apikey,urldashboard)
getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,count)

    
