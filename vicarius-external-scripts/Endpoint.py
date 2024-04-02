#Author: Joaldir Rani

import requests
import json

def getCountEndpoints(apikey,urldashboard):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

def getEndpoints(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        parsed = json.loads(response.text)        
        
    except:
        print("something is wrong, will try again....")

    strEndpoints = ""
    
    for i in parsed['serverResponseObject']:
        #print(json.dumps(i,indent=2))
        #print(i['endpointOperatingSystem']['operatingSystemName'])

        endpointUpdatedAt = str((i['endpointUpdatedAt']))
        operatingSystemName = (i['endpointOperatingSystem']['operatingSystemName'])
        agentVersion = (i['endpointVersion']['versionName'])
        strEndpoints += (str(i['endpointId']) + "," + i['endpointName'] + "," + i['endpointHash'] + "," + operatingSystemName + "," + agentVersion + "," + endpointUpdatedAt +"\n")
    
    return strEndpoints

def getEndpoitsExternalAttributesCount(apikey,urldashboard):
    
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpointAttributes/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        responsecount = parsed['serverResponseCount']
        
    except:
        print("something is wrong, will try again....")
    
    return responsecount


def getEndpoitsExternalAttributes(apikey,urldashboard,fr0m,siz3):
    
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpointAttributes/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    #print(json.dumps(parsed['serverResponseCount'],indent=2))
    #print(json.dumps(jresponse['serverResponseObject'],indent=2))
    strEndpointsAttributes = ""
    for i in parsed['serverResponseObject']:
        #print(i)
        #print(i['endpointAttributesEndpoint']['endpointId'])
        endpointId = i['endpointAttributesEndpoint']['endpointId']
        #print(i['endpointAttributesEndpoint']['endpointName'])
        endpointName = i['endpointAttributesEndpoint']['endpointName']
        #print(i['endpointAttributesEndpoint']['endpointName'])
        #print(i['endpointAttributesAttribute']['attributeExternalId'])
        value = (i['endpointAttributesAttribute']['attributeExternalId'])
        #print(i['endpointAttributesAttribute']['attributeAttributeSource']['attributeSourceName'])
        attrib = (i['endpointAttributesAttribute']['attributeAttributeSource']['attributeSourceName'])
        strEndpointsAttributes += (str(endpointId) + "," + endpointName + "," + attrib + "," + value + "\n")
        #print(attrib+":"+value)
    
    return strEndpointsAttributes

def getEndpointScoresExploitabilityRiskFactors(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'includeFields': 'endpointId,endpointEndpointScores,endpointName',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    strEndpointsExploitabilityRiskFactors = ""
    for i in parsed['serverResponseObject']:
        endpointId = i['endpointId']
        endpointName = i['endpointName']
        #print(i['endpointScoresExploitabilityRiskFactors'])
        for j in i['endpointEndpointScores']['endpointScoresExploitabilityRiskFactors']:
            riskFactorTerm = j['riskFactorTerm']
            riskFactorDescription = j['riskFactorDescription']            
            #print(j['riskFactorTerm'])
            #print(j['riskFactorDescription'])
            strEndpointsExploitabilityRiskFactors += (str(endpointId) + "," + endpointName + "," + riskFactorTerm + "," + riskFactorDescription + "\n")
        
    return strEndpointsExploitabilityRiskFactors

def getEndpointScoresImpactRiskFactors(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'includeFields': 'endpointId,endpointEndpointScores,endpointName',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    strEndpointScoresImpactRiskFactors = ""
    for i in parsed['serverResponseObject']:
        endpointId = i['endpointId']
        endpointName = i['endpointName']

        for j in i['endpointEndpointScores']['endpointScoresImpactRiskFactors']:
            riskFactorTerm = j['riskFactorTerm']
            riskFactorScore = j['riskFactorScore']            
            strEndpointScoresImpactRiskFactors += (str(endpointId) + "," + endpointName + "," + riskFactorTerm + "," + str(riskFactorScore) + "\n")

    return strEndpointScoresImpactRiskFactors

   



                

