#Author: Joaldir Rani

import requests
import json
import utils
import datetime

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

        if i['organizationEndpointVulnerabilitiesPatch']['patchId'] > 0:
            patchid = str(i['organizationEndpointVulnerabilitiesPatch']['patchId'])
            patchName = (i['organizationEndpointVulnerabilitiesPatch']['patchName'])
            patchReleaseDate = str(i['organizationEndpointVulnerabilitiesPatch']['patchReleaseDate'])
        else:
            patchid = "n\\a"
            patchName = "n\\a"
            patchReleaseDate = "n\\a"

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

        strVulnerabilities += (asset + "," + productName + "," + productRawEntryName + "," + sensitivityLevelName + "," + cve + "," + patchid + "," + patchName + "," + patchReleaseDate + "," + createAt + "," + updateAt + "," + link + ",\"" + vulnerabilitySummary + "\"\n")
    
    return strVulnerabilities

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
    
    lstCVEs = []

    for i in parsed['serverResponseObject']:

        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        productRawEntryName = productRawEntryName.replace(',',"").replace(";","")
        vulid = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId']
        link = 'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + str(vulid)
        
        if i['organizationEndpointVulnerabilitiesPatch']['patchId'] > 0:
            patchid = str(i['organizationEndpointVulnerabilitiesPatch']['patchId'])
            patchName = (i['organizationEndpointVulnerabilitiesPatch']['patchName'])
            dt = datetime.datetime.fromtimestamp(i['organizationEndpointVulnerabilitiesPatch']['patchReleaseDate'])
            patchReleaseDate = dt.strftime('%Y-%m-%d')
            
        else:
            patchid = "n\\a"
            patchName = "n\\a"
            patchReleaseDate = "n\\a"

        strCve = cve + ",\"" + productRawEntryName + "\",\"" + link + "\"," + patchid + "," + patchName + "," + patchReleaseDate

        lstCVEs.append(strCve)
    
    return lstCVEs