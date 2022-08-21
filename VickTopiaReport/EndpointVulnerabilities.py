#Author: Joaldir Rani

import requests
import json
import utils

def getCountEvents(apikey,urldashboard):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    return responsecount

def getCountCVEs(apikey,urldashboard,endpointName):
    
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointName==' + endpointName,

    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort' : '+organizationEndpointVulnerabilitiesCreatedAt',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
        parsed = json.loads(response.text)
  
    except:
        print("something is wrong, will try again....")

    strVulnerabilities = ""
    for i in parsed['serverResponseObject']:
        
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        vulid = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId']
        #https://www.vicarius.io/research-center/vulnerability/CVE-2020-8927-id263765
        link = 'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + str(vulid)
        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
        except:
            productName = ""

        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        sensitivityLevelName = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        
        vulnerabilitySummary = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySummary'] 
        vulnerabilitySummary = str(vulnerabilitySummary).replace("\"","'")
        
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        try:
            createAt = utils.timestamptodatetime(i['organizationEndpointVulnerabilitiesCreatedAt'])
            updateAt = utils.timestamptodatetime(i['organizationEndpointVulnerabilitiesUpdatedAt'])
        except:
            createAt = ""
            updateAt = ""

        productName = productName.replace(',',"").replace(";","")
        productRawEntryName = productRawEntryName.replace(',',"").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("\r","").replace("\n",">>")
        vulnerabilitySummary = vulnerabilitySummary.replace(",","").replace(";","")

        strVulnerabilities += (asset + "," + productName + "," + productRawEntryName + "," + sensitivityLevelName + "," + cve + ",\"" + vulnerabilitySummary + "\"," + link + "," + createAt + "," + updateAt + "\n")
    
    return strVulnerabilities

def getCVEsbyEndpointName(apikey,urldashboard,fr0m,siz3,endpointName):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointName==' + endpointName,
        'sort' : '+organizationEndpointVulnerabilitiesCreatedAt',
    }

    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
        parsed = json.loads(response.text)
  
    except:
        print("something is wrong, will try again....")

    strCVEs = ""
    for i in parsed['serverResponseObject']:
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        
        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
        except:
            productName = ""        
        
        productName = productName.replace(',',"").replace(";","")
        strCVEs += ( asset + "," + cve + "," + productName + "\n")
    
    return strCVEs    

    