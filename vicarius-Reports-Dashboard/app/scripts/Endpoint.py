#Author: Joaldir Rani
import requests
import json
from datetime import datetime
import time

def getCountEndpoints(apikey,urldashboard):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
        'sort': '+endpointId'
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']
        firstID = jsonresponse['serverResponseObject'][0]['endpointId']

    except:
        print("something is wrong, will try again....")
        print("response: ",response.text)

    return responsecount,firstID

def getEndpoints(apikey,urldashboard,fr0m,siz3,lastEID):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort': '+endpointId',
        'q': 'endpointId>' + str(lastEID)
    }
    print("gettingEndpoints -> Endpoints.py")
    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/endpoint/search', params=params, headers=headers)
        parsed = json.loads(response.text)    
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpoints(apikey,urldashboard,fr0m,siz3)
        
    except:
        print("something is wrong, will try again....")
    print("Status Code: " + str(response.status_code))
    #print(parsed)
    strEndpoints = ""
    strEPStatus = ""
    jsonEndpoints = []
    jsonEPStatus = []

    runtime = datetime.now()
    for i in parsed['serverResponseObject']:
        deployment_date = str(i['endpointCreatedAt'])
        last_connected = str((i['endpointUpdatedAt']))
        operatingSystemName = (i['endpointOperatingSystem']['operatingSystemName'])
        agentVersion = (i['endpointVersion']['versionName'])
        alive = (i['endpointAlive'])
        if alive == "true":
            now = datetime.now()
            LastContact = now.strftime('%Y-%m-%dT%H:%M:%S')
        else:
            LastContact = datetime.fromtimestamp(int(last_connected) / 1000).isoformat()
        tokenGenTimeUNX = (i['endpointTokenGenerationTime'])
        tokenGenTime = datetime.fromtimestamp(int(tokenGenTimeUNX) / 1000).isoformat()
        deploymentDateUNX = i['endpointCreatedAt']
        deploymentDate = datetime.fromtimestamp(int(deploymentDateUNX) / 1000).isoformat()
        try:
            substatus = i['endpointEndpointSubStatus']['endpointSubStatusName']
        except: 
            substatus = ""
        try: 
            connectedbyProxy = i['endpointConnectedByProxy']
        except:
            connectedbyProxy = ""
        listEndpoints = {
            'endpointId': i['endpointId'],
            'endpointName': i['endpointName'],
            'endpointHash': i['endpointHash'],
            'alive': str(alive),
            'operatingSystemName': operatingSystemName,
            'agentVersion': agentVersion,
            'substatus': substatus,
            'connectedbyProxy': str(connectedbyProxy),
            'tokenGenTime': tokenGenTime,
            'deployment_date': deployment_date,
            'last_connected': last_connected,
            'deploymentDate': deploymentDate,
            'LastContact': LastContact
        }
        jsonEndpoints.append(listEndpoints)
        # Constructing the list of dictionaries for EP status
        listEPStatus = {
            'endpointId': i['endpointId'],
            'endpointName': i['endpointName'],
            'endpointHash': i['endpointHash'],
            'alive': str(alive),
            'connectedbyProxy': str(connectedbyProxy),
            'LastContact': LastContact,
            'runtime': str(runtime)
        }
        jsonEPStatus.append(listEPStatus)
        #strEndpoints += ("'" + str(i['endpointId']) + "','" + i['endpointName'] + "','" + i['endpointHash'] + "','" + str(alive) + "','" + operatingSystemName + "','" + agentVersion + "','" + substatus + "','" + str(connectedbyProxy) + "','" + tokenGenTime + "','" + deployment_date + "','" + last_connected + "','" + deploymentDate + "','" + LastContact + "'\n")
        #strEPStatus += ("'" + str(i['endpointId']) + "','" + i['endpointName'] + "','" + i['endpointHash'] + "','" + str(alive) + "','" + str(connectedbyProxy) + "','"  + LastContact + "','" + str(runtime) + "'\n")
    #print(jsonEndpoints)
    return jsonEndpoints,jsonEPStatus

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
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpoitsExternalAttributesCount(apikey,urldashboard)
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
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpoitsExternalAttributes(apikey,urldashboard,fr0m,siz3)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    #print(json.dumps(parsed['serverResponseCount'],indent=2))
    #print(json.dumps(parsed['serverResponseObject'],indent=2))
    strEndpointsAttributes = ""
    endpointsAttributesObj = []
    for i in parsed['serverResponseObject']:
        try:
            endpointId = i['endpointAttributesEndpoint']['endpointId']
            endpointName = i['endpointAttributesEndpoint']['endpointName']
            endpointHash = i['endpointAttributesEndpoint']['endpointHash']
            value = (i['endpointAttributesAttribute']['attributeExternalId'])
            attrib = (i['endpointAttributesAttribute']['attributeAttributeSource']['attributeSourceName'])
            strEndpointsAttributes += (str(endpointId) + "," + endpointName + "," + attrib + "," + value + "\n")
            #print(attrib+":"+value)
            epattriJson = {
                "endpointId": endpointId,
                "endpointName": endpointName,
                "endpointHash": endpointHash,
                "attrib": attrib,
                "value": value
            }
            endpointsAttributesObj.append(epattriJson)
        except:
            print("error!! next")

    
    return strEndpointsAttributes,endpointsAttributesObj

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
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointScoresExploitabilityRiskFactors(apikey,urldashboard,fr0m,siz3)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    strEndpointsExploitabilityRiskFactors = ""
    objEndpointsExploitabilityRiskFactors = []
    for i in parsed['serverResponseObject']:
        endpointId = i['endpointId']
        endpointName = i['endpointName']
        #print(i['endpointScoresExploitabilityRiskFactors'])
        for j in i['endpointEndpointScores']['endpointScoresExploitabilityRiskFactors']:
            riskFactorTerm = j['riskFactorTerm']
            riskFactorDescription = j['riskFactorDescription']            
            strEndpointsExploitabilityRiskFactors += (str(endpointId) + "," + endpointName + "," + riskFactorTerm + "," + riskFactorDescription + "\n")
            epExploitRisk = {
                "endpointId": endpointId,
                "endpointName": endpointName,
                "riskFactorTerm": riskFactorTerm,
                "riskFactorDescription": riskFactorDescription,
            }
            objEndpointsExploitabilityRiskFactors.append(epExploitRisk)
    return strEndpointsExploitabilityRiskFactors,objEndpointsExploitabilityRiskFactors

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
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointScoresImpactRiskFactors(apikey,urldashboard,fr0m,siz3)
        parsed = json.loads(response.text)
        
    except:
        print("something is wrong, will try again....")

    strEndpointScoresImpactRiskFactors = ""
    objEndpointScoresImpactRiskFactors = []
    for i in parsed['serverResponseObject']:
        endpointId = i['endpointId']
        endpointName = i['endpointName']

        for j in i['endpointEndpointScores']['endpointScoresImpactRiskFactors']:
            riskFactorTerm = j['riskFactorTerm']
            riskFactorScore = j['riskFactorScore']            
            strEndpointScoresImpactRiskFactors += (str(endpointId) + "," + endpointName + "," + riskFactorTerm + "," + str(riskFactorScore) + "\n")
            epimpactRiskfactors= {
                "endpointId": endpointId,
                "endpointName": endpointName,
                "riskFactorTerm": riskFactorTerm,
                "riskFactorScore": riskFactorScore
            }
            objEndpointScoresImpactRiskFactors.append(epimpactRiskfactors)
    return strEndpointScoresImpactRiskFactors,objEndpointScoresImpactRiskFactors
