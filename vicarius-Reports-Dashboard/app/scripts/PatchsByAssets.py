import requests
import json
from datetime import datetime
import time

def getCountEndpointsPatchs(apikey,urldashboard,endpointHash,trycount=0):
    errors = []
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': '0',
        'size': '500',
        'group': 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId',
        'includeOriginalDoc': 'false',
        'newParser': 'true',
        'objectName': 'OrganizationEndpointExternalReferenceExternalReferences',        
        'sort': 'OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank',
        'subAggregationLevel': '0',
        'sumLastSubAggregationBuckets': '0',
        'q': 'organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=('+endpointHash+')',
    }
    if (trycount < 2):
        try:
            response = requests.get(urldashboard + '/vicarius-external-data-api/aggregation/searchGroup?', params=params, headers=headers)
            if response.status_code == 429:
                print("API Rate Limit exceeded ... Waiting and Trying again")
                errors.append("API Rate Limit")
                time.sleep(60)
                trycount += 1
                getCountEndpointsPatchs(apikey,urldashboard,endpointHash,)
            jsonresponse = json.loads(response.text)
            responsecount = jsonresponse['serverResponseCount']

        except Exception as e:
            errors.append(f"Exception: {e}, EndpointHash: {endpointHash}")
            print(f'something is wrong, will try again- EndpointHash: {endpointHash}, ')
            time.sleep(60)
            trycount += 1
            getCountEndpointsPatchs(apikey,urldashboard,endpointHash,trycount)
    else:
        print(f'Try count exceeded - EndpointHash: {endpointHash} ')
        responsecount = 0
        jsonresponse = 0 
    try:
        return responsecount, jsonresponse, errors
    except Exception as e:
        errors.append(f"Return Exception: {e},")
        jsonresponse = {}
        return 0, jsonresponse, errors

def getCountEndpointsPatchsApps(apikey,urldashboard,endpointHash):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': '0',
        'size': '1',
        'group': 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId',
        'includeOriginalDoc': 'false',
        'newParser': 'true',
        'objectName': 'OrganizationEndpointExternalReferenceExternalReferences',        
        'sort': 'OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank',
        'subAggregationLevel': '0',
        'sumLastSubAggregationBuckets': '0',
        'q': 'organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=('+endpointHash+');externalReferenceId=in=(-1,1947539,-1,1972712,-1,2030761,4897281,-1,1826256,-1,4142147,1552707)',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/aggregation/searchGroup?', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getCountEndpointsPatchsApps(apikey,urldashboard,endpointHash)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")
    try:
        return responsecount
    except:
        return 0

def getEndpointsPatchsold(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointHash):
    patch_list = []

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'group': 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchReleaseDate;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId',
        'includeOriginalDoc': 'false',
        'newParser': 'true',
        'objectName': 'OrganizationEndpointExternalReferenceExternalReferences',
        'sort': 'OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank',
        'subAggregationLevel': '0',
        'sumLastSubAggregationBuckets': '0',
        'q': 'organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointName=='+endpointName,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/aggregation/searchGroup?', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointHash)
        parsed = json.loads(response.text)
          
    except:
        print("something is wrong, will try again....")
        return endpointName

    strPatchEndpoints = ""
    for i in parsed['serverResponseObject']:
        sensitivityLevelRanks = ''
        sensitivityLevelNames = ''
        patchDescriptions = ''
        patchDescriptions = ''
        externalReferenceSourceIds = ''    
        patchReleaseDates = 0
        
        for j in i['aggregationAggregations']:
            
            if 'sensitivityLevelRanks' in j['aggregationName']:
                sensitivityLevelRanks = j['aggregationId'] 
            if 'sensitivityLevelNames' in j['aggregationName']:
                sensitivityLevelNames = j['aggregationId']
            if 'patchDescriptions' in j['aggregationName']:
                patchDescriptions = j['aggregationId']
            if 'patchReleaseDates' in j['aggregationName']:
                patchReleaseDates = j['aggregationId']
            if 'externalReferenceIds' in j['aggregationName']:
                for x in j['aggregationAggregations']:
                    if 'patchIds' in x['aggregationName']:
                        patchId = x['aggregationId']
                    #print(x['aggregationAggregations'])
                    for y in x['aggregationAggregations']:
                        if 'externalReferenceSourceIds' in y['aggregationName']:
                            #print(y['aggregationId'])
                            externalReferenceSourceIds = y['aggregationId']
        if patchReleaseDates != 0:
            if len(patchReleaseDates) == 13:
                patchReleaseDates = datetime.fromtimestamp(int(patchReleaseDates) / 1000).isoformat()
            else: 
                patchReleaseDates = None               
                
        else:
            patchReleaseDates = None

        if patchReleaseDates == None:
            now = datetime.now()
            patchReleaseDates = now


        #print(sensitivityLevelRanks + "," +  sensitivityLevelNames + "," + patchDescriptionsexternalReferenceIds + "," + patchDescriptions)
        #strPatchEndpoints += ("\"" + endpointName + "\",\"" + endpointSO + "\",\"" + i['aggregationId'] + "\",\"" + sensitivityLevelRanks + "\",\"" +  sensitivityLevelNames + "\",\"" + patchDescriptions + "\",\"" + externalReferenceSourceIds + "\"\n")
        #Asset,SO,PatchName,SeverityLevel,SeverityName,Description,PatchID\
        patch_dict = {
            "endpointHash": endpointHash,
            "endpointName": endpointName,
            "endpointSO": endpointSO,
            "PatchName": i['aggregationId'], # Assuming 'i' is replaced by 'data' for clarity
            "patchId": patchId,
            "sensitivityLevelRanks": sensitivityLevelRanks,
            "sensitivityLevelNames": sensitivityLevelNames,
            "patchDescriptions": patchDescriptions,
            "patchreleasedate": patchReleaseDates,
            "externalReferenceSourceIds": externalReferenceSourceIds
        }
        patch_list.append(patch_dict)

    totalPatchs = len(parsed['serverResponseObject'])
    return patch_list, totalPatchs

def getEndpointsPatchs(apikey, urldashboard, fr0m, siz3, min_date, max_date, endpointName, endpointHash):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'group': 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchReleaseDate;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId',
        'includeOriginalDoc': 'false',
        'newParser': 'true',
        'objectName': 'OrganizationEndpointExternalReferenceExternalReferences',
        'sort': 'OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank',
        'subAggregationLevel': '0',
        'sumLastSubAggregationBuckets': '0',
        'q': 'organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=='+endpointHash,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/aggregation/searchGroup?', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointsPatchs(apikey, urldashboard, fr0m, siz3, min_date, max_date, endpointName, endpointHash)
        parsed = json.loads(response.text)
          
    except:
        print("something is wrong, will try again....")
        time.sleep(30)
        getEndpointsPatchs(apikey, urldashboard, fr0m, siz3, min_date, max_date, endpointName, endpointHash)

    return parsed

def parseEndpointpatches(parsed,endpointName,endpointHash):
    patch_list = []
    strPatchEndpoints = ""
    for i in parsed['serverResponseObject']:
        sensitivityLevelRanks = ''
        sensitivityLevelNames = ''
        patchDescriptions = ''
        patchDescriptions = ''
        externalReferenceSourceIds = ''    
        patchReleaseDates = 0
        
        for j in i['aggregationAggregations']:
            
            if 'sensitivityLevelRanks' in j['aggregationName']:
                sensitivityLevelRanks = j['aggregationId'] 
            if 'sensitivityLevelNames' in j['aggregationName']:
                sensitivityLevelNames = j['aggregationId']
            if 'patchDescriptions' in j['aggregationName']:
                patchDescriptions = j['aggregationId']
            if 'patchReleaseDates' in j['aggregationName']:
                patchReleaseDates = j['aggregationId']
            if 'externalReferenceIds' in j['aggregationName']:
                for x in j['aggregationAggregations']:
                    if 'patchIds' in x['aggregationName']:
                        patchId = x['aggregationId']
                    #print(x['aggregationAggregations'])
                    for y in x['aggregationAggregations']:
                        if 'externalReferenceSourceIds' in y['aggregationName']:
                            #print(y['aggregationId'])
                            externalReferenceSourceIds = y['aggregationId']
        if patchReleaseDates != 0:
            if len(patchReleaseDates) == 13:
                patchReleaseDates = datetime.fromtimestamp(int(patchReleaseDates) / 1000).isoformat()
            else: 
                patchReleaseDates = None               
                
        else:
            patchReleaseDates = None

        if patchReleaseDates == None:
            now = datetime.now()
            patchReleaseDates = now


        #print(sensitivityLevelRanks + "," +  sensitivityLevelNames + "," + patchDescriptionsexternalReferenceIds + "," + patchDescriptions)
        #strPatchEndpoints += ("\"" + endpointName + "\",\"" + endpointSO + "\",\"" + i['aggregationId'] + "\",\"" + sensitivityLevelRanks + "\",\"" +  sensitivityLevelNames + "\",\"" + patchDescriptions + "\",\"" + externalReferenceSourceIds + "\"\n")
        #Asset,SO,PatchName,SeverityLevel,SeverityName,Description,PatchID\
        patch_dict = {
            "endpointHash": endpointHash,
            "endpointName": endpointName,
            "PatchName": i['aggregationId'], # Assuming 'i' is replaced by 'data' for clarity
            "patchId": patchId,
            "sensitivityLevelRanks": sensitivityLevelRanks,
            "sensitivityLevelNames": sensitivityLevelNames,
            "patchDescriptions": patchDescriptions,
            "patchreleasedate": patchReleaseDates,
            "externalReferenceSourceIds": externalReferenceSourceIds
        }
        patch_list.append(patch_dict)

    totalPatchs = len(parsed['serverResponseObject'])
    return patch_list



