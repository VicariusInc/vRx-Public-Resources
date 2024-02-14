#Author: Joaldir Rani

import requests
import json
import time

def getCountEvents(apikey,urldashboard,lastdate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
        'q' : 'organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>' + str(lastdate)
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'q': 'organizationEndpointVulnerabilitiesCreatedAt>'+str(minDate)+';organizationEndpointVulnerabilitiesCreatedAt<'+str(maxDate)+';organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=('+endpointHash+')', #.endpointName==' + endpointName,
        'sort' : '-organizationEndpointVulnerabilitiesCreatedAt',
    }
    jresponse = []
    try:
        time.sleep(1)
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
        jresponse = json.loads(response.text)
  
    except:
        print("something is wrong, will try again....")
        time.sleep(30)
        getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)

    return jresponse

def parseEndpointVulnerabilities(jresponse,endpointGroups):
    strVulnerabilities = ""

    for i in jresponse['serverResponseObject']:
        
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        vulid = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId'])
        link = 'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + vulid
        # fix for empty product name for OS
        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
        except:
            try: 
                productName = i['organizationEndpointVulnerabilitiesOperatingSystem']['operatingSystemName']
            except:
                productName = ""
    
        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        sensitivityLevelName = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        
        vulnerabilitySummary = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySummary'] 
        vulnerabilitySummary = str(vulnerabilitySummary).replace("\"","'")
        
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        endpointHash = i['organizationEndpointVulnerabilitiesEndpoint']['endpointHash']

        if i['organizationEndpointVulnerabilitiesPatch']['patchId'] > 0:
            patchid = str(i['organizationEndpointVulnerabilitiesPatch']['patchId'])
            patchName = (i['organizationEndpointVulnerabilitiesPatch']['patchName'])
            #handle exception when patchReleaseDate not present
            try: 
                patchReleaseDate = str(i['organizationEndpointVulnerabilitiesPatch']['patchReleaseDate'])
            except: 
                patchReleaseDate = "n\\a"
        else:
            patchid = "n\\a"
            patchName = "n\\a"
            patchReleaseDate = "n\\a"

        try:
            createAt = i['organizationEndpointVulnerabilitiesCreatedAt']
            updateAt = i['organizationEndpointVulnerabilitiesUpdatedAt']
        except:
            createAt = ""
            updateAt = ""

        productName = productName.replace(',',"").replace(";","")
        productRawEntryName = productRawEntryName.replace(',',"").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("\r","").replace("\n",">>")
        vulnerabilitySummary = vulnerabilitySummary.replace(",","").replace(";","")
        
        #threatLevelId = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['threatLevelId'])
        vulnerabilityV3ExploitabilityLevel = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3ExploitabilityLevel'])
        vulnerabilityV3BaseScore = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3BaseScore'])

        #for group in endpointGroups.split("|"):
        strVulnerabilities += (asset + "," + endpointHash + ",group," + productName + "," + productRawEntryName + "," + sensitivityLevelName + "," + cve + "," + vulid + "," + patchid + "," + patchName + "," + patchReleaseDate + "," + str(createAt) + "," + str(updateAt) + "," + link + ",\"" + vulnerabilitySummary + "\"," +vulnerabilityV3BaseScore + "," + vulnerabilityV3ExploitabilityLevel + "\n")

        maxDate = createAt

    return strVulnerabilities,maxDate