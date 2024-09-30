#Author: Joaldir Rani

import requests
import json
import time
import datetime
import utils
from datetime import datetime

def safe_convert_to_datetime(timestamp, default_value=None):
    """Safely convert a timestamp to datetime, handling seconds/milliseconds and errors."""
    if default_value is None:
        default_value = datetime.now()  # Or any other default datetime

    try:
        # Check if the timestamp is likely in milliseconds (large numbers)
        if timestamp > 1e10:  # Adjust threshold as necessary
            timestamp /= 1000.0  # Convert from milliseconds to seconds

        return datetime.fromtimestamp(timestamp)
    except (TypeError, ValueError, OverflowError):
        return default_value

def get_days_diff_from_timestamp(timestamp_ms):
    # Converter timestamp em milissegundos para objeto datetime
    dt = datetime.datetime.fromtimestamp(timestamp_ms / 1000.0)

    # Obter a data atual
    current_date = datetime.datetime.now().date()

    # Calcular a diferença em dias entre as duas datas
    diff = current_date - dt.date()

    # Retornar a diferença em dias
    return diff.days

def getCountEvents(apikey,urldashboard,lastdate):
    errors = []
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

    try:
        return responsecount
    except:
        return 0

def getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount=0):
    errors = []
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 500,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=('+endpointHash+')',
        'includeFields' : 'organizationEndpointVulnerabilitiesEndpoint.endpointId,organizationEndpointVulnerabilitiesEndpoint.endpointHash,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceExternalId,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityId,organizationEndpointVulnerabilitiesProduct.productName,organizationEndpointVulnerabilitiesOperatingSystem.operatingSystemName,organizationEndpointVulnerabilitiesVersion.versionName,organizationEndpointVulnerabilitiesSubVersion.subVersionName,organizationEndpointVulnerabilitiesProductRawEntry.productRawEntryName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySensitivityLevel.sensitivityLevelName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySummary,organizationEndpointVulnerabilitiesEndpoint.endpointName,organizationEndpointVulnerabilitiesPatch.patchId,organizationEndpointVulnerabilitiesPatch.patchName,organizationEndpointVulnerabilitiesPatch.patchReleaseDate,organizationEndpointVulnerabilitiesCreatedAt,organizationEndpointVulnerabilitiesUpdatedAt,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3ExploitabilityLevel,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3BaseScore'
    }
    if (trycount < 2):
        try:
            response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
            if response.status_code == 429:
                print("API Rate Limit exceeded ... Waiting and Trying again")
                errors.append("API Rate Limit")
                time.sleep(60)
                trycount += 1
                getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount)
            jsonresponse = json.loads(response.text)
        except Exception as e:
                print(f'something is wrong, will try again- EndpointHash: {endpointHash}, ')
                errors.append(f"Exception: {e}, EndpointHash: {endpointHash}")
                time.sleep(60)
                trycount += 1
                getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount)
    #print (jsonresponse)
    
    try:
        responsecount = int(jsonresponse['serverResponseCount'])
    except:
        responsecount = 0
        
    
    try: 
        return responsecount, jsonresponse, errors
    except Exception as e:
        errors.append(f"Return Exception: {e},")
        jsonresponse = {}
        return 0, jsonresponse, errors
 
def getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=('+endpointHash+')',
        'includeFields' : 'organizationEndpointVulnerabilitiesEndpoint.endpointId,organizationEndpointVulnerabilitiesEndpoint.endpointHash,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceExternalId,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityId,organizationEndpointVulnerabilitiesProduct.productName,organizationEndpointVulnerabilitiesOperatingSystem.operatingSystemName,organizationEndpointVulnerabilitiesVersion.versionName,organizationEndpointVulnerabilitiesSubVersion.subVersionName,organizationEndpointVulnerabilitiesProductRawEntry.productRawEntryName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySensitivityLevel.sensitivityLevelName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySummary,organizationEndpointVulnerabilitiesEndpoint.endpointName,organizationEndpointVulnerabilitiesPatch.patchId,organizationEndpointVulnerabilitiesPatch.patchName,organizationEndpointVulnerabilitiesPatch.patchReleaseDate,organizationEndpointVulnerabilitiesCreatedAt,organizationEndpointVulnerabilitiesUpdatedAt,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3ExploitabilityLevel,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3BaseScore'
    }
    #jresponse = []
    try:
        time.sleep(0.5)
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
        jresponse = json.loads(response.text)
  
    except:
        print("something is wrong, will try again....")
        time.sleep(30)
        getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
    #if response.status_code == 429:
    #    print("API Rate Limit exceeded ... Waiting and Trying again")
    #    time.sleep(60)
    #    getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)

    try: 
        return jresponse
    except:
        jresponse = {}
        return jresponse

def parseEndpointVulnerabilities(apikey,urldashboard,jresponse): #endpointGroups):
    
    vulns_list = []

    for i in jresponse['serverResponseObject']:
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        vulid = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId'])
        link = "https://www.vicarius.io/vsociety/vulnerabilities/"+vulid+"/"+cve
        #'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + vulid
        
        typecve = ""

        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
            typecve = "App"
        except:
            productName = ""

        try:
            productName = i['organizationEndpointVulnerabilitiesOperatingSystem']['operatingSystemName']
            typecve = "SO"
        except:
            if (typecve != "App"):
                productName = ""

        try:
            version = i['organizationEndpointVulnerabilitiesVersion']['versionName']
        except:
            version = ""
        try:
            subVersion = i['organizationEndpointVulnerabilitiesSubVersion']['subVersionName']
        except:
            subVersion = productRawEntryName

        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        sensitivityLevelName = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        
        vulnerabilitySummary = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySummary'] 
        vulnerabilitySummary = str(vulnerabilitySummary).replace("\"","'")
        
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        endpointId = (i['organizationEndpointVulnerabilitiesEndpoint']['endpointId'])
        endpointHash = i['organizationEndpointVulnerabilitiesEndpoint']['endpointHash']

        if i['organizationEndpointVulnerabilitiesPatch']['patchId'] > 0:
            patchid = str(i['organizationEndpointVulnerabilitiesPatch']['patchId'])
            patchName = (i['organizationEndpointVulnerabilitiesPatch']['patchName'])
            try:
                patchReleaseDate = i['organizationEndpointVulnerabilitiesPatch']['patchReleaseDate']
            except:
                patchReleaseDate = 0
            #patchFileName = str(i['organizationEndpointVulnerabilitiesPatch']['patchFileName'])
        else:
            patchid = "0"
            patchName = "n\\a"
            patchReleaseDate = 0
            #patchFileName = "n\\a"

        try:
            createAttimemille = i['organizationEndpointVulnerabilitiesCreatedAt']
            createAt = utils.timestamptodatetime(createAttimemille)
            updateAt = i['organizationEndpointVulnerabilitiesUpdatedAt']
            updateAt = utils.timestamptodatetime(updateAt)
        except:
            createAt = ""
            updateAt = ""

        productName = productName.replace(',',"").replace(";","")
        productRawEntryName = productRawEntryName.replace(',',"").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("\r","").replace("\n",">>")
        vulnerabilitySummary = vulnerabilitySummary.replace(",","").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("'","")
        
        #threatLevelId = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['threatLevelId'])
        vulnerabilityV3ExploitabilityLevel = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3ExploitabilityLevel'])
        vulnerabilityV3BaseScore = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3BaseScore'])
    
        if patchReleaseDate < 1:
            patchReleaseDate = createAttimemille

        hpatchReleaseDate = safe_convert_to_datetime(patchReleaseDate)


        vulnerability_dict = {
            "endpointId" : endpointId,
            "asset": asset,
            "endpointHash": endpointHash,
            "productName": productName,
            "productRawEntryName": productRawEntryName,
            "sensitivityLevelName": sensitivityLevelName,
            "cve": cve,
            "vulid": vulid,
            "patchid": patchid,
            "patchName": patchName,
            "patchReleaseDate": patchReleaseDate,
            "patchReleaseDateTimeStamp": hpatchReleaseDate,
            "createAt": createAt,
            "updateAt": updateAt,
            "link": link,
            "vulnerabilitySummary": vulnerabilitySummary,
            "vulnerabilityV3BaseScore": vulnerabilityV3BaseScore,
            "vulnerabilityV3ExploitabilityLevel": vulnerabilityV3ExploitabilityLevel,
            "typecve": typecve,
            "version": version,
            "subversion": subVersion
        }

        vulns_list.append(vulnerability_dict)


    return vulns_list 
    