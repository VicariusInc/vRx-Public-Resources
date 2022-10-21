#Author: Joaldir Rani
import requests
import json

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
    try:
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']
    except:
        print("something is wrong, will try again....")

    return responsecount

def getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
    }
    
    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointPublisherProductVersions/search', params=params, headers=headers)
        parsed = json.loads(response.text)

    except:
        print("Something is wrong")

    strEndpointsProductVersions = ""

    for i in parsed['serverResponseObject']:
        asset = (i['organizationEndpointPublisherProductVersionsEndpoint']['endpointName'])
        productName = (i['organizationEndpointPublisherProductVersionsApplication']['applicationName']).replace(',',' ')
        productRawEntryName = (i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName']).replace(',',' ')
        operatingSystemFamilyName = (i['organizationEndpointPublisherProductVersionsOperatingSystemFamily']['operatingSystemFamilyName'])
        try:
            productId = "p" + str(i['organizationEndpointPublisherProductVersionsProduct']['productId'])
        except:
            productId = "a" + str((i['organizationEndpointPublisherProductVersionsApplication']['applicationId']))
                    
        endpointId = str(i['organizationEndpointPublisherProductVersionsEndpoint']['endpointId'])
        
        try:
            publisherName = (i['organizationEndpointPublisherProductVersionsPublisher']['publisherName']).replace(',',' ')
        except:
            publisherName = (i['organizationEndpointPublisherProductVersionsProductRawEntry']['productRawEntryName']).replace(',','')

        try:
            productVersion = str((i['organizationEndpointPublisherProductVersionsVersion']['versionName'])).replace(',','.')
        except:
            productVersion = "-"

        strEndpointsProductVersions += (asset + "," + productName + "," + productRawEntryName + "," + productVersion + "," + publisherName + "," + operatingSystemFamilyName + "," + endpointId + "," + productId + "\n")
        
    return strEndpointsProductVersions    
                


    