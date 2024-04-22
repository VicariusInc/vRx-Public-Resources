#Author: Joaldir Rani

import requests
import json

def getAssetsbySearchQueryCount(apikey,urldashboard,searchQuery):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
        'Charset': 'utf-8', 
        'Content-Type': 'application/json',
    }

    params = {
        'from': 0,
        'includeFields': 'endpointName',
        'size': 1,
    }

    data = searchQuery

    try: 
        response = requests.get(
            urldashboard + '/vicarius-external-data-api/endpoint/search',
            params=params,
            headers=headers,
            data=data,
        )
        jresponse = json.loads(response.text)
        responsecount = jresponse['serverResponseCount']
        #print(json.dumps(jresponse,indent=2))

    except:
        print('Something is wrong to obtain assets in group')
    
    return responsecount

def getAssetsbySearchQuery(apikey,urldashboard,searchQuery,fr0m,siz3):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
        'Charset': 'utf-8', 
        'Content-Type': 'application/json',
    }

    params = {
        'from': fr0m,
        'includeFields': 'endpointName,endpointId,endpointHash',
        'size': siz3,
    }

    data = searchQuery

    try: 
        response = requests.get(
            urldashboard + '/vicarius-external-data-api/endpoint/search',
            params=params,
            headers=headers,
            data=data,
        )
        jresponse = json.loads(response.text)
        #print(json.dumps(jresponse,indent=2))

    except:
        print('Something is wrong to obtain assets in group')

    endpointsNames = ""
    endpointIds = ""
    endpointHashs = ""

    for i in jresponse['serverResponseObject']:
        endpointName = i['endpointName']
        endpointsNames += endpointName + "|"
        endpointId = str(i['endpointId'])
        endpointIds += endpointId + "|"
        endpointHash = str(i['endpointHash'])
        endpointHashs += endpointHash + "|"

    endpointsNames = endpointsNames[:-1]
    endpointIds = endpointIds[:-1]    
    endpointHashs = endpointHashs[:-1]    

    return endpointsNames,endpointIds,endpointHashs


def getEndpointGroups(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort': '-organizationEndpointGroupUpdatedAt',
    }

    try: 
        response = requests.get(
            urldashboard + '/vicarius-external-data-api/organizationEndpointGroup/search', 
            params=params, 
            headers=headers
        )
        jresponse = json.loads(response.text)

    except:
        print('Something is wrong to obtain grups')
    
    groupNames = ""

    for i in jresponse['serverResponseObject']:
        groupName = i['organizationEndpointGroupName']
        groupSearchQuery = i['organizationEndpointGroupSearchQueries']
        groupNames += groupName +"||"+ groupSearchQuery + "\n"

    return groupNames

def getEndpointGroupsCount(apikey,urldashboard):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointGroup/search', params=params, headers=headers)
        parsed = json.loads(response.text)
        responsecount = parsed['serverResponseCount']

    except:
        print('problem get number of groups')
    
    return responsecount