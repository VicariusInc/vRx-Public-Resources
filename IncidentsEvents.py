import requests
import json
import utils
import time

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

def getIncidentesEventsCountbyType(apikey,urldashboard,incidenttype,minDate,maxDate):
    #MitigatedVulnerability
    #DetectedVulnerability

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': '0',
        'size': '1',
        'group': 'incidentEventIncidentEventType&metricActionName=IncidentEvent',
        'q': 'analyticsEventCreatedAtNano>'+minDate+';analyticsEventCreatedAtNano<'+maxDate+';incidentEventIncidentEventType=in=('+incidenttype+')',
        'sort': '-analyticsEventCreatedAtNano',
    }
    
    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/count', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

def getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'group': 'incidentEventIncidentEventType&metricActionName=IncidentEvent',
        'q': 'analyticsEventCreatedAtNano>'+minDate+';analyticsEventCreatedAtNano<'+maxDate+';incidentEventIncidentEventType=in=('+incidenttype+')',
        'sort': '-analyticsEventCreatedAtNano',
    }
    
    jresponse = None
    attempts = 0

    while jresponse is None and attempts < 3:
        try:
            response = requests.get(urldashboard + '/vicarius-external-data-api/incidentEvent/filter', params=params, headers=headers)
            jresponse = json.loads(response.text)
        except Exception as e:
            print(f"Erro ao obter resposta: {e}. Tentando novamente em 5 segundos...")
            time.sleep(5)
            attempts += 1        
    
    return jresponse

def parseIncidentEventsbyType(jresponse):
        
    strIncidentEvents = ""

    for i in jresponse['serverResponseObject']:
        #print(json.dumps(i,indent=2))
        eventType = i['incidentEventIncidentEventType']
        asset = i['incidentEventEndpoint']['endpointName']
        assetId = i['incidentEventEndpoint']['endpointId']
        try:
            cve = i['incidentEventVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        except:
            cve = "Error"
            
        try:
            cvss = i['incidentEventVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        except:
            cvss = "Error"

        
        vulnerabilitySummary = i['incidentEventVulnerability']['vulnerabilitySummary']
        try:
            threatLevelId = i['incidentEventVulnerability']['vulnerabilitySensitivityLevel'].get('threatLevelId', '0')
        except:
            threatLevelId = "Error"

        vulnerabilityV3ExploitabilityLevel = i['incidentEventVulnerability']['vulnerabilityV3ExploitabilityLevel']
        vulnerabilityV3BaseScore = i['incidentEventVulnerability']['vulnerabilityV3BaseScore']
        patchId = i.get('patchId', '0')
        vulnerabilitySummary = vulnerabilitySummary.replace(",","|").replace("\n","").replace("\r","").replace(";","|")

        analyticsEventCreatedAt = str(i['analyticsEventCreatedAt'])
        #analyticsEventCreatedAt = utils.timestamptodatetime(i['analyticsEventCreatedAt'])
        analyticsEventUpdatedAt = str(i['analyticsEventUpdatedAt'])
        #analyticsEventUpdatedAt = utils.timestamptodatetime(i['analyticsEventUpdatedAt'])
        maxDate = i['analyticsEventCreatedAtNano']
        
        #publisher vulneratbilit
        #print(i['incidentEventVulnerability']['vulnerabilityPublishedAt'])
        
        if i.get('incidentEventOrganizationPublisherOperatingSystems') is not None:
            try:
                if i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsPublisher'].get('publisherName') is not None:
                    publisher = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsPublisher']['publisherName'])
                    #print(publisher)
                else:
                    publisher = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsPublisher']['publisherId'])
            except:
                publisher = "Error"
                
                
            systemOperation = (i['incidentEventOrganizationPublisherOperatingSystems']['organizationPublisherOperatingSystemsOperatingSystem']['operatingSystemName'])
            strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(systemOperation) + "," + str(threatLevelId) 
                + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
                    + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
        
        else:       
            try:
                if i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsPublisher'].get('publisherName') is not None:
                    publisher = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsPublisher']['publisherName'])
                
                else:
                    publisher = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsPublisher']['publisherId'])
            except:
                publisher = "Error"

            try:
                product = (i['incidentEventOrganizationPublisherProducts']['organizationPublisherProductsProduct']['productName'])
            except:
                product = ""
            
            strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(threatLevelId) 
                + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
                    + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
            #strIncidentEvents += (str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
    
    return strIncidentEvents,maxDate