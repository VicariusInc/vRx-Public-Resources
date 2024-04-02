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
    responsecount = {'serverResponseCount':0}
    
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
        print(response.headers)
        print('Something is wrong to obtain assets in group')
    
    #print (jresponse)
    responsecount = jresponse['serverResponseCount']
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
        'includeFields': 'endpointName',
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

    for i in jresponse['serverResponseObject']:
        endpointName = i['endpointName']
        endpointsNames += endpointName + "|"
    
    return endpointsNames


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