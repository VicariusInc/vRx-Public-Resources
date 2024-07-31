#Arthor Jordan Hamblen
import requests
import json
from datetime import datetime
import time
#Get all apps per Risk score
## Report for getting Vulnerabilities with app risk level as a whole 
### AppName 

def getallAppwithPatch(apikey,urldashboard):
    headers = {
      'Content-Type': 'application/json',
      'Vicarius-Token': apikey,
      'Cookie': 'Vicarius-Token=' + apikey
    }
    params = {
        'from': 0,
        'size': 10,
        'objectName': 'OrganizationPublisherProducts',
        'group': 'organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName',
        'includeOriginalDoc': 'false',
    }
    
    payload = json.dumps([
      {
        "searchQueryName": "appPatch",
        "searchQueryObjectName": "OrganizationEndpointPublisherProductHashtags",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationEndpointPublisherProductHashtagsHashtag.hashtagTag=in=(#has_patch)",
        "searchQueryQueryJoinType": ""
      }
    ])
    url = '/vicarius-external-data-api/aggregation/searchGroup?'
    response = requests.request("GET",urldashboard + url, params=params, headers=headers, data=payload)
    jsonresponse = json.loads(response.text)
    #print(jsonresponse)
    sro = jsonresponse['serverResponseObject']
    #print(sro)
    lowRiskApps = 0
    mediumRiskApps = 0
    highRiskApps = 0
    for i in sro:
        if "Low" in i['aggregationId']:
            lowRiskApps = i['aggregationCount']
            #print(lowRiskApps)
        if "Medium" in i['aggregationId']:
            mediumRiskApps = i['aggregationCount']
            #print(mediumRiskApps)
        if "High" in i['aggregationId']:
            highRiskApps = i['aggregationCount']
            #print(highRiskApps)      
    return lowRiskApps,mediumRiskApps,highRiskApps

def getallApp(apikey,urldashboard):
    headers = {
      'Content-Type': 'application/json',
      'Vicarius-Token': apikey,
      'Cookie': 'Vicarius-Token=' + apikey
    }
    params = {
        'from': 0,
        'size': 10,
        'objectName': 'OrganizationPublisherProducts',
        'group': 'organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName',
        'includeOriginalDoc': 'false',
    }
    
    payload = json.dumps([
      {
        "searchQueryName": "appPatch",
        "searchQueryObjectName": "OrganizationEndpointPublisherProductHashtags",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationEndpointPublisherProductHashtagsHashtag.hashtagTag=in=(#has_patch)",
        "searchQueryQueryJoinType": ""
      }
    ])
    url = '/vicarius-external-data-api/aggregation/searchGroup?'
    response = requests.request("GET",urldashboard + url, params=params, headers=headers)
    jsonresponse = json.loads(response.text)
    if response.status_code == 429:
        print("API Rate Limit exceeded ... Waiting and Trying again")
        time.sleep(60)
        getallApp(apikey,urldashboard)
    #print(jsonresponse)
    sro = jsonresponse['serverResponseObject']
    #print(sro)
    lowRiskApps = 0
    mediumRiskApps = 0
    highRiskApps = 0
    for i in sro:
        if "Low" in i['aggregationId']:
            lowRiskApps = i['aggregationCount']
            #print(lowRiskApps)
        if "Medium" in i['aggregationId']:
            mediumRiskApps = i['aggregationCount']
            #print(mediumRiskApps)
        if "High" in i['aggregationId']:
            highRiskApps = i['aggregationCount']
            #print(highRiskApps)      
    return lowRiskApps,mediumRiskApps,highRiskApps
   
def getAppswithRiskandPatch(apikey,urldashboard,riskLevel,fr0m,siz3):

    url = urldashboard + "/vicarius-external-data-api/organizationPublisherProducts/search?from=" + str(fr0m) + "&size=" + str(siz3) + "&sort=-organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresScore%3BpublisherProductHash&q=&includeFields=publisherProductHash%2CorganizationPublisherProductsUpdatedAt%2CorganizationPublisherProductsProduct.productName%2CorganizationPublisherProductsProduct.productId%2CorganizationPublisherProductsProduct.productUniqueIdentifier%2CorganizationPublisherProductsPublisher.publisherName%2CorganizationPublisherProductsPublisher.publisherId%2CorganizationPublisherProductsPhoto.photoId%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresScore%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresImpactRiskFactors%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresExploitabilityRiskFactors%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName"

    payload = json.dumps([
      {
        "searchQueryName": "apps",
        "searchQueryObjectName": "OrganizationPublisherProducts",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName=in=(" + riskLevel +")",
        "searchQueryQueryJoinType": ""
      },
      {
        "searchQueryName": "appPatch",
        "searchQueryObjectName": "OrganizationEndpointPublisherProductHashtags",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationEndpointPublisherProductHashtagsHashtag.hashtagTag=in=(#has_patch)",
        "searchQueryQueryJoinType": ""
      }
    ])
    headers = {
      'Content-Type': 'application/json',
      'Vicarius-Token': apikey,
      'Cookie': 'Vicarius-Token=' + apikey
    }

    response = requests.request("GET", url, headers=headers, data=payload)

    #print(response.text)
    jsonresponse = json.loads(response.text)
    sro = jsonresponse['serverResponseObject']
    appObj = []
    #print(sro)
    for i in sro:
        publisherHash = i['publisherProductHash']
        productId = i['organizationPublisherProductsProduct']['productId']
        productName = i['organizationPublisherProductsProduct']['productName']
        appRiskLevel = i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresSensitivityLevel']['sensitivityLevelName']
        appRiskScore = i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresScore']
        productUpdatedAt = i['organizationPublisherProductsUpdatedAt']
        productUpdatedAt =  datetime.fromtimestamp(productUpdatedAt / 1000).isoformat()
        VulnerabilityCVSS = ""
        predictedAttackSurface = ""
        hasPatch = ""
        vulExploit = ""
        for imr in i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresImpactRiskFactors']:
            if "HighVulnerabilityCVSS" in imr['riskFactorTerm']:
                VulnerabilityCVSS = imr['riskFactorTerm']
            if "HighPredictedAttackSurface" in imr['riskFactorTerm']:
                predictedAttackSurface = imr['riskFactorTerm']
        for imr in i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresExploitabilityRiskFactors']:
            if "#has_patch" in imr['riskFactorDescription']:
                hasPatch = imr['riskFactorDescription']
            if "#new_vulnerability_published" in imr['riskFactorDescription']:
                vulExploit = imr['riskFactorDescription']
        appjson = {
            "appName": productName,
            "productID": productId,
            "publisherHash": publisherHash,
            "riskLevel": appRiskLevel,
            "riskScore": appRiskScore,
            "vulRiskFactor": VulnerabilityCVSS,
            "predictedAttackSurface": predictedAttackSurface,
            "patch": hasPatch,
            "vulExploit": vulExploit,
            "ProductUpdatedAt": productUpdatedAt
        }
        appObj.append(appjson)
    return appObj

def getAppswithRisk(apikey,urldashboard,riskLevel,fr0m,siz3):

    url = urldashboard + "/vicarius-external-data-api/organizationPublisherProducts/search?from=" + str(fr0m) + "&size=" + str(siz3) + "&sort=-organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresScore%3BpublisherProductHash&q=&includeFields=publisherProductHash%2CorganizationPublisherProductsUpdatedAt%2CorganizationPublisherProductsProduct.productName%2CorganizationPublisherProductsProduct.productId%2CorganizationPublisherProductsProduct.productUniqueIdentifier%2CorganizationPublisherProductsPublisher.publisherName%2CorganizationPublisherProductsPublisher.publisherId%2CorganizationPublisherProductsPhoto.photoId%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresScore%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresImpactRiskFactors%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresExploitabilityRiskFactors%2CorganizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName"

    payload = json.dumps([
      {
        "searchQueryName": "apps",
        "searchQueryObjectName": "OrganizationPublisherProducts",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationPublisherProductsOrganizationPublisherProductsScores.organizationPublisherProductsScoresSensitivityLevel.sensitivityLevelName=in=(" + riskLevel +")",
        "searchQueryQueryJoinType": ""
      },
      {
        "searchQueryName": "appPatch",
        "searchQueryObjectName": "OrganizationEndpointPublisherProductHashtags",
        "searchQueryObjectJoinByFieldName": "publisherProductHash",
        "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
        "searchQueryQuery": "organizationEndpointPublisherProductHashtagsHashtag.hashtagTag=in=(#has_patch)",
        "searchQueryQueryJoinType": ""
      }
    ])
    headers = {
      'Content-Type': 'application/json',
      'Vicarius-Token': apikey,
      'Cookie': 'Vicarius-Token=' + apikey
    }

    response = requests.request("GET", url, headers=headers)

    #print(response.text)
    jsonresponse = json.loads(response.text)
    sro = jsonresponse['serverResponseObject']
    appObj = []
    #print(sro)
    for i in sro:
        publisherHash = i['publisherProductHash']
        productId = i['organizationPublisherProductsProduct']['productId']
        productName = i['organizationPublisherProductsProduct']['productName']
        appRiskLevel = i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresSensitivityLevel']['sensitivityLevelName']
        appRiskScore = i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresScore']
        productUpdatedAt = i['organizationPublisherProductsUpdatedAt']
        productUpdatedAt =  datetime.fromtimestamp(productUpdatedAt / 1000).isoformat()
        VulnerabilityCVSS = ""
        predictedAttackSurface = ""
        hasPatch = ""
        vulExploit = ""
        for imr in i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresImpactRiskFactors']:
            if "HighVulnerabilityCVSS" in imr['riskFactorTerm']:
                VulnerabilityCVSS = imr['riskFactorTerm']
            if "HighPredictedAttackSurface" in imr['riskFactorTerm']:
                predictedAttackSurface = imr['riskFactorTerm']
        for imr in i['organizationPublisherProductsOrganizationPublisherProductsScores']['organizationPublisherProductsScoresExploitabilityRiskFactors']:
            if "#has_patch" in imr['riskFactorDescription']:
                hasPatch = imr['riskFactorDescription']
            if "#new_vulnerability_published" in imr['riskFactorDescription']:
                vulExploit = imr['riskFactorDescription']
        appjson = {
            "appName": productName,
            "productID": productId,
            "publisherHash": publisherHash,
            "riskLevel": appRiskLevel,
            "riskScore": appRiskScore,
            "vulRiskFactor": VulnerabilityCVSS,
            "predictedAttackSurface": predictedAttackSurface,
            "patch": hasPatch,
            "vulExploit": vulExploit,
            "ProductUpdatedAt": productUpdatedAt
        }
        appObj.append(appjson)
    return appObj
