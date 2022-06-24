#Author: Joaldir Rani

from datetime import datetime
from email.mime import application
import requests
import json
import datetime
import sys
import time

apikey = ''
urldashboard = ''

f = open('VickyReportApiEndpointPublisherProductVersions.csv', 'a', encoding='UTF8')

f.write('Asset,productName,productRawEntryName,productVersion,publisherName,operatingSystemFamilyName,endpointId,applicationId\n')

def getCountEndpointPublisherProductVersions(apikey,urldashboard):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointPublisherProductVersions/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def timestamptodatetime(timestamp_with_ms):

    timestamp, ms = divmod(timestamp_with_ms, 1000)
    dt = datetime.datetime.fromtimestamp(timestamp) + datetime.timedelta(milliseconds=ms)    
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
  
    return formatted_time

def getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3,count):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        #'sort' : 'organizationEndpointVulnerabilitiesEndpoint.endpointName',
    }
    
    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointPublisherProductVersions/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        #print(json.dumps(parsed, indent=4, sort_keys=True))
    except:
        time.sleep(60)
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointPublisherProductVersions/search', params=params, headers=headers)
        parsed = json.loads(response.text)

    
    for i in parsed['serverResponseObject']:
        asset = (i['organizationEndpointPublisherProductVersionsEndpoint']['endpointName'])
        productName = (i['organizationEndpointPublisherProductVersionsApplication']['applicationName']).replace(',',' ')
        productRawEntryName = (i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName']).replace(',',' ')
        operatingSystemFamilyName = (i['organizationEndpointPublisherProductVersionsOperatingSystemFamily']['operatingSystemFamilyName'])
        applicationId = str((i['organizationEndpointPublisherProductVersionsApplication']['applicationId']))
        endpointId = str((i['organizationEndpointPublisherProductVersionsEndpoint']['endpointId']))
        
        #print(json.dumps(i, indent=4, sort_keys=True))
        print(i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName'])
        print(i['organizationEndpointPublisherProductVersionsApplication']['applicationId'])
        print(i['organizationEndpointPublisherProductVersionsEndpoint']['endpointName'])
        print(i['organizationEndpointPublisherProductVersionsEndpoint']['endpointId'])

        try:
            print(i['organizationEndpointPublisherProductVersionsPublisher']['publisherName'])
            publisherName = (i['organizationEndpointPublisherProductVersionsPublisher']['publisherName']).replace(',',' ')
        except:
            print(i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName'])
            publisherName = (i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName']).replace(',','')

        print(i['organizationEndpointPublisherProductVersionsOperatingSystemFamily']['operatingSystemFamilyName'])
        
        try:
            print(i['organizationEndpointPublisherProductVersionsVersion']['versionName'])
            productVersion = str((i['organizationEndpointPublisherProductVersionsVersion']['versionName'])).replace(',','.')
        except:
            print("version")
            productVersion = "-"

        f.write(asset + "," + productName + "," + productRawEntryName + "," + productVersion + "," + publisherName + "," + operatingSystemFamilyName + "," + endpointId + "," + applicationId + "\n")
        
                
    fr0m = fr0m + siz3

    if fr0m < count:
        time.sleep(3)
        getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3,count)
    else:
        f.close()
        sys.exit()
    
fr0m = 0
siz3 = 50
count = getCountEndpointPublisherProductVersions(apikey,urldashboard)
print(count)
getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3,count)

    