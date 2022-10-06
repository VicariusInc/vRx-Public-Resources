import requests
import json

def getIncidentesEventsCount(apikey,urldashboard):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': '0',
        'size': '1',
        'q': 'incidentEventIncidentEventType=in=(MitigatedVulnerability,DetectedVulnerability)',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/count', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

def getIncidentesEventsCountbyType(apikey,urldashboard,incidenttype):
    #MitigatedVulnerability
    #DetectedVulnerability

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': '0',
        'size': '1',
        'q': 'incidentEventIncidentEventType=in=('+incidenttype+')',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/count', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

def getIncidentEvents(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,        
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/filter', params=params, headers=headers)
        parsed = json.loads(response.text)

    except:
        print("something is wrong, will try again....")

    strIncidentEvents = ""

    for i in parsed['serverResponseObject']:

        eventType = i['incidentEventIncidentEventType']
        asset = i['incidentEventEndpoint']['endpointName']
        cve = i['incidentEventVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        cvss = i['incidentEventVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        analyticsEventUpdatedAt = str(i['analyticsEventUpdatedAt'])

        try:

            publisher = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsPublisher']['publisherName'])
            systemOperation = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsOperatingSystem']['operatingSystemName'])
            
            strIncidentEvents += (asset + "," + cve + "," + cvss + "," + eventType + "," + publisher + "," + systemOperation + "," + analyticsEventUpdatedAt + "\n")

        except:
        
            publisher = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsPublisher']['publisherName'])
            product = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsProduct']['productName'])
            strIncidentEvents += (asset + "," + cve + "," + cvss + "," + eventType + "," + publisher + "," + product + "," + analyticsEventUpdatedAt + "\n")

    return strIncidentEvents

def getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype):
    #MitigatedVulnerability
    #DetectedVulnerability

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'q': 'incidentEventIncidentEventType=in=('+incidenttype+')',
        'sort': '+analyticsEventUpdatedAt',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/filter', params=params, headers=headers)
        parsed = json.loads(response.text)

    except:
        print("something is wrong, will try again....")

    strIncidentEvents = ""

    for i in parsed['serverResponseObject']:

        eventType = i['incidentEventIncidentEventType']
        asset = i['incidentEventEndpoint']['endpointName']
        cve = i['incidentEventVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        cvss = i['incidentEventVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        analyticsEventUpdatedAt = str(i['analyticsEventUpdatedAt'])

        try:

            publisher = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsPublisher']['publisherName'])
            systemOperation = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsOperatingSystem']['operatingSystemName'])
            
            strIncidentEvents += (asset + "," + cve + "," + cvss + "," + eventType + "," + publisher + "," + systemOperation + "," + analyticsEventUpdatedAt + "\n")

        except:
        
            publisher = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsPublisher']['publisherName'])
            product = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsProduct']['productName'])
            strIncidentEvents += (asset + "," + cve + "," + cvss + "," + eventType + "," + publisher + "," + product + "," + analyticsEventUpdatedAt + "\n")

    return strIncidentEvents