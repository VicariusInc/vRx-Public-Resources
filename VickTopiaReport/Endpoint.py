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
        strEndpoints += (str(i['endpointId']) + "," + i['endpointName'] + "," + i['endpointHash'] +"\n")
    
    return strEndpoints

