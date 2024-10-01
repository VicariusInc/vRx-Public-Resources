#Author: Joaldir Rani

import requests
import json
import time

def getAssetsbyGroupID(apikey,urldashboard,groupName,groupId,fr0m,siz3,trycount=0):
     
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

    payload = json.dumps([
        {
            "searchQueryName": "assetsGroup",
            "searchQueryObjectName": "OrganizationEndpointGroup",
            "searchQueryObjectJoinByFieldName": "endpointId",
            "searchQueryObjectJoinByForeignFieldName": "endpointId",
            "searchQueryQuery": f"organizationEndpointGroupId=in=({groupId})",
            "searchQueryQueryFetchMode": "PrefetchIds"
        }
    ])

    try: 
        response = requests.get(
            urldashboard + '/vicarius-external-data-api/endpoint/search',
            params=params,
            headers=headers,
            data=payload,
        )
        while response.status_code == 429 and trycount < 2:
            ("API Rate Limit exceeded ... Waiting and Trying again")
            
            time.sleep(60)
            response = requests.get(
                urldashboard + '/vicarius-external-data-api/endpoint/search',
                params=params,
                headers=headers,
                data=payload,
            )
            trycount += 1
            jresponse = json.loads(response.text)
            src = jresponse['serverResponseCount']
            
        if trycount >= 2:
            print("API Rate Limit exceeded .")
            src = 0 
        else: 
            jresponse = json.loads(response.text)
            src = jresponse['serverResponseCount']

        #(f'params:{params}, body:{payload}, url:{urldashboard}/vicarius-external-data-api/endpoint/search')
        jresponse = json.loads(response.text)
        #responsecount = jresponse['serverResponseCount']
        #print(json.dumps(jresponse,indent=2))

    except:
        print('Something is wrong to obtain assets in group')
        src = 0 

    return src,[{'groupId': groupId, 'groupName': groupName,'endpointName': i['endpointName'], 'endpointId': i['endpointId'], 'endpointHash': i['endpointHash']}
            for i in jresponse.get('serverResponseObject', [])]

def getEndpointGroupsID(apikey, urldashboard, fr0m, siz3, trycount=0):
    print("new Group query by ID ")
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
        #print(response.text)
        while response.status_code == 429 and trycount < 2:
            ("API Rate Limit exceeded ... Waiting and Trying again")
            
            time.sleep(60)
            response = requests.get(
                urldashboard + '/vicarius-external-data-api/organizationEndpointGroup/search', 
                params=params, 
                headers=headers
            )
            trycount += 1
            jresponse = json.loads(response.text)
            src = jresponse['serverResponseCount']
            
        if trycount >= 2:
            print("API Rate Limit exceeded .")
            src = 0 
        else: 
            jresponse = json.loads(response.text)
            src = jresponse['serverResponseCount']
        jresponse = response.json()
        print("*********************")

        #print(f'headers')
    except requests.RequestException as e:
        print(f"Error fetching groups: {e}")
        src = 0 
        return []

    return src,[{'groupName': i['organizationEndpointGroupName'], 'groupID': i['organizationEndpointGroupId'], 'groupTeam': i['organizationEndpointGroupOrganizationTeam']['organizationTeamName'], 'groupTeamId': i['organizationEndpointGroupOrganizationTeam']['organizationTeamId']}
            for i in jresponse.get('serverResponseObject', [])]
