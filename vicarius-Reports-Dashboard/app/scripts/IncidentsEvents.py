import requests
import json
import utils
import time
from datetime import datetime

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
        'sort': '+analyticsEventCreatedAtNano',
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
    
    if response.status_code == 429:
        print("API Rate Limit exceeded ... Waiting and Trying again")
        time.sleep(60)
        getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate)
        
    return jresponse

def parseIncidentEventsbyType(jresponse):

    incident_list = []
    
        
    #strIncidentEvents = ""

    for i in jresponse['serverResponseObject']:
        #print(json.dumps(i,indent=2))
        eventType = i['incidentEventIncidentEventType']
        asset = i['incidentEventEndpoint']['endpointName']
        assetId = i['incidentEventEndpoint']['endpointId']
        assetHash = i['incidentEventEndpoint']['endpointHash']
        try:
            cve = i['incidentEventVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        except:
            cve = "Error"
            
        try:
            cvss = i['incidentEventVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        except:
            cvss = "Error"

        if eventType == "MitigatedVulnerability" :
            MitigatedEventDetectionDate = i['incidentEventDetecetdDate']
        else:
            MitigatedEventDetectionDate = 0
        
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
        try:
            CreatedAt = datetime.fromtimestamp(int(analyticsEventCreatedAt) / 1000).isoformat()
            UpdatedAt = datetime.fromtimestamp(int(analyticsEventUpdatedAt) / 1000).isoformat()
        except Exception as e:
            print(f"Error at converting timestamp: {e}")
            CreatedAt = 0
            UpdatedAt = 0
        analyticsEventCreatedAtNano = str(i['analyticsEventCreatedAtNano'])
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
            
            #converting to json response for fixing db insert error
            #strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(systemOperation) + "," + str(threatLevelId) 
            #    + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
            #        + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
            incident_dict = {
            "assetId": assetId,
            "asset": asset,
            "assetHash": assetHash,
            "cve": cve,
            "cvss": cvss,
            "eventType": eventType,
            "publisher": publisher,
            "product": systemOperation,
            "threatLevelId": threatLevelId,
            "vulnerabilityV3ExploitabilityLevel": vulnerabilityV3ExploitabilityLevel,
            "vulnerabilityV3BaseScore": vulnerabilityV3BaseScore,
            "patchId": patchId,
            "vulnerabilitySummary": vulnerabilitySummary,
            "created_at_milli": analyticsEventCreatedAt,
            "updated_at_milli": analyticsEventUpdatedAt,
            "create_at_nano": analyticsEventCreatedAtNano,
            "created_at": CreatedAt,
            "updated_at": UpdatedAt,
            "mitigated_event_detected_at": MitigatedEventDetectionDate
            }
            incident_list.append(incident_dict)

        
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
            
            #strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(threatLevelId) 
            #    + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
            #        + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
            #strIncidentEvents += (str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
            incident_dict = {
                "assetId": assetId,
                "asset": asset,
                "assetHash": assetHash,
                "cve": cve,
                "cvss": cvss,
                "eventType": eventType,
                "publisher": publisher,
                "product": product,
                "threatLevelId": threatLevelId,
                "vulnerabilityV3ExploitabilityLevel": vulnerabilityV3ExploitabilityLevel,
                "vulnerabilityV3BaseScore": vulnerabilityV3BaseScore,
                "patchId": patchId,
                "vulnerabilitySummary": vulnerabilitySummary,
                "created_at_milli": analyticsEventCreatedAt,
                "updated_at_milli": analyticsEventUpdatedAt,
                "create_at_nano": analyticsEventCreatedAtNano,
                "created_at": CreatedAt,
                "updated_at": UpdatedAt,
                "mitigated_event_detected_at": MitigatedEventDetectionDate
            }
            incident_list.append(incident_dict)
    
    #return strIncidentEvents,maxDate

    return incident_list,maxDate

def getEventsCountbyType(apikey,urldashboard,incidenttype,minDate,maxDate):
    #NewEndpoint
    #NewPublisherProduct
    #NewPublisherOperatingSystem
    #EndpointRemoved
    #ImpersonationAttempt

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

def getEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate):
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

def parseEventsbyType(jresponse):

    incident_list = []
    
        
    #strIncidentEvents = ""
    #print(jresponse['serverResponseObject'])
    for i in jresponse['serverResponseObject']:
        print(i)
        #print(json.dumps(i,indent=2))
        eventType = i['incidentEventIncidentEventType']
        try:
            asset = i['incidentEventEndpoint']['endpointName']
            assetId = i['incidentEventEndpoint']['endpointId']
        except:
            asset = "n/a"
            assetId = "n/a"


        analyticsEventCreatedAt = str(i['analyticsEventCreatedAt'])
        #analyticsEventCreatedAt = utils.timestamptodatetime(i['analyticsEventCreatedAt'])
        analyticsEventUpdatedAt = str(i['analyticsEventUpdatedAt'])
        CreatedAt = datetime.fromtimestamp(int(analyticsEventCreatedAt) / 1000).isoformat()
        UpdatedAt = datetime.fromtimestamp(int(analyticsEventUpdatedAt) / 1000).isoformat()
        analyticsEventCreatedAtNano = str(i['analyticsEventCreatedAtNano'])
        #analyticsEventUpdatedAt = utils.timestamptodatetime(i['analyticsEventUpdatedAt'])
        maxDate = i['analyticsEventCreatedAtNano']
        
        #publisher vulneratbilit
        #print(i['incidentEventVulnerability']['vulnerabilityPublishedAt'])
        
        if "NewPublisherProduct" or "NewPublisherOperatingSystem" in eventType:
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
                
                #converting to json response for fixing db insert error
                #strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(systemOperation) + "," + str(threatLevelId) 
                #    + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
                #        + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
                incident_dict = {
                "assetId": assetId,
                "asset": asset,
                "eventType": eventType,
                "publisher": publisher,
                "product": systemOperation,
                "created_at_milli": analyticsEventCreatedAt,
                "updated_at_milli": analyticsEventUpdatedAt,
                "create_at_nano": analyticsEventCreatedAtNano,
                "created_at": CreatedAt,
                "updated_at": UpdatedAt
                }
                incident_list.append(incident_dict)


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
                
                #strIncidentEvents += (str(assetId) + "," + str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(threatLevelId) 
                #    + "," + str(vulnerabilityV3ExploitabilityLevel) + "," + str(vulnerabilityV3BaseScore) + "," + str(patchId) + "," + str(vulnerabilitySummary) + "," 
                #        + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
                #strIncidentEvents += (str(asset) + "," + str(cve) + "," + str(cvss) + "," + eventType + "," + str(publisher) + "," + str(product) + "," + str(analyticsEventCreatedAt) + "," + str(analyticsEventUpdatedAt) + "\n")
                incident_dict = {
                    "assetId": assetId,
                    "asset": asset,
                    "eventType": eventType,
                    "publisher": publisher,
                    "product": product,
                    "created_at_milli": analyticsEventCreatedAt,
                    "updated_at_milli": analyticsEventUpdatedAt,
                    "create_at_nano": analyticsEventCreatedAtNano,
                    "created_at": CreatedAt,
                    "updated_at": UpdatedAt
                }
                incident_list.append(incident_dict)
        elif "NewEndpoint" or "EndpointRemoved" in eventType:
            try:
                publisher = (i['incidentEventEndpoint']['endpointEndpointExternalReferences']['endpointExternalReferencesExternalReference']['externalReferenceExternalId'])
            except:
                publisher = "Error"
            try:
                product = (i['incidentEventEndpoint']['endpointOperatingSystem']['operatingSystemName'])
            except:
                product = "Error"
            incident_dict = {
                "assetId": assetId,
                "asset": asset,
                "eventType": eventType,
                "publisher": publisher,
                "product": product,
                "created_at_milli": analyticsEventCreatedAt,
                "updated_at_milli": analyticsEventUpdatedAt,
                "create_at_nano": analyticsEventCreatedAtNano,
                "created_at": CreatedAt,
                "updated_at": UpdatedAt
            }
            incident_list.append(incident_dict)
    #return strIncidentEvents,maxDate

    return incident_list,maxDate

def getxProtectEventsCountbyType(apikey,urldashboard,incidenttype,minDate,maxDate):
    #ImpersonationAttempt

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

def getxProtectEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate):
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

def parsexProtectEventsbyType(jresponse):
    incident_list = []

    for i in jresponse['serverResponseObject']:
        #print(json.dumps(i,indent=2))
        eventType = i['incidentEventIncidentEventType']
        asset = i['incidentEventEndpoint']['endpointName']
        assetId = i['incidentEventEndpoint']['endpointId']

        analyticsEventCreatedAt = str(i['analyticsEventCreatedAt'])
        #analyticsEventCreatedAt = utils.timestamptodatetime(i['analyticsEventCreatedAt'])
        analyticsEventUpdatedAt = str(i['analyticsEventUpdatedAt'])
        CreatedAt = datetime.fromtimestamp(int(analyticsEventCreatedAt) / 1000).isoformat()
        UpdatedAt = datetime.fromtimestamp(int(analyticsEventUpdatedAt) / 1000).isoformat()
        analyticsEventCreatedAtNano = str(i['analyticsEventCreatedAtNano'])
        #analyticsEventUpdatedAt = utils.timestamptodatetime(i['analyticsEventUpdatedAt'])
        maxDate = i['analyticsEventCreatedAtNano']
        
        #publisher vulneratbilit
        #print(i['incidentEventVulnerability']['vulnerabilityPublishedAt'])
        
        vicproductName = i['incidentEventPublisherProductProcesses']['publisherProductProcessesProduct']['productName']
        srcparentprocessName = i['incidentEventParentProcess']['processName']
        srcprocessName = i['incidentEventProcess']['processName']
        srcuser = i['incidentEventAttributes']['attributeExternalId']
        status = "N/A" #taskStatusId
        incident_dict = {
            "assetId": assetId,
            "asset": asset,
            "eventType": eventType,
            "victimprocess": vicproductName,
            "srcparentprocessName": srcparentprocessName,
            "srcprocessName": srcprocessName,
            "srcuser": srcuser,
            "status": status,
            "created_at_milli": analyticsEventCreatedAt,
            "updated_at_milli": analyticsEventUpdatedAt,
            "create_at_nano": analyticsEventCreatedAtNano,
            "created_at": CreatedAt,
            "updated_at": UpdatedAt
        }
        incident_list.append(incident_dict)
    #return strIncidentEvents,maxDate

    return incident_list,maxDate

