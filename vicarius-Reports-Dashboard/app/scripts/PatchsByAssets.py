import requests
import json
from datetime import datetime

def getCountEndpointsPatchs(apikey,urldashboard,endpointHash):

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
        'q': 'organizationEndpointExternalReferenceExternalReferencesEndpoint.endpointHash=in=('+endpointHash+')',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/aggregation/searchGroup?', params=params, headers=headers)
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

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
        jsonresponse = json.loads(response.text)
        responsecount = jsonresponse['serverResponseCount']

    except:
        print("something is wrong, will try again....")

    return responsecount

def getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointHash):

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