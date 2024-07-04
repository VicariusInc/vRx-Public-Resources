#Author: Joaldir Rani
#changed
import argparse
from tqdm import tqdm
import time
import pandas as pd
import MitigationTime as mt
import cleanData as cd
import numpy as np
import os 
import shutil
import gc



import json

import VickyState as state
import EndpointsEventTask as tasks
import EndpointVulnerabilities as vuln
import Endpoint as assets
import PatchsByAssets as patchs
import EndpointPublisherProductVersions as products
import IncidentsEvents as incidents
import EndpointGroups as groups
import DatabaseConnector as db
import updateExternalScore as updExSc
import apprisk as apprisk


#from urllib.request import urlopen

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

errorList = [] 
def read_secret(secret_name):
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        print(f"Unable to read the secret: {secret_name}")
        return None

DEFAULT_QUERY_LIMIT_PER_MINUTE = 55

# Track the last time a query was made
last_query_time = 0

def control_rate(query_limit=None):
    global last_query_time

        # Use the default rate limit if none is provided
    if query_limit is None:
        query_limit = DEFAULT_QUERY_LIMIT_PER_MINUTE

    # Calculate the time since the last query
    elapsed_time = time.time() - last_query_time

    # If less than a minute has passed since the last query, wait
    if elapsed_time < 60:
        # Calculate the time to sleep based on the desired rate
        sleep_time = max(0, (60 / query_limit) - elapsed_time)
        time.sleep(sleep_time)

    # Update the last query time
    last_query_time = time.time()

parser = argparse.ArgumentParser(description='Args for VikyTopiaReport')
parser.add_argument('-k', '--api-key', dest='apiKey', action='store', required=False, help='Topia API key')
parser.add_argument('-d', '--dashboard', dest='dashboard', action='store', required=False, help='Url dashboard ex. https://xxxx.vicarius.cloud')
parser.add_argument('--allreports', dest='allreports', action='store_true', help='All Reports')
parser.add_argument('-a', '--assetsreport', dest='assetsreport', action='store_true', help='Assets Reports')
parser.add_argument('-t', '--taskreport', dest='tasksreport', action='store_true', help='Task Reports')
parser.add_argument('-v', '--vulnerabilitiesreport', dest='vulnreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-p', '--patchsreport', dest='patchsreport', action='store_true', help='Patchs Versions Reports')
parser.add_argument('-hp', '--hasPatchAppsreport', dest='hasPatchAppsreport', action='store_true', help='Apps by Risk Level with Has_Patch')
parser.add_argument('-i', '--incidentvulnerability', dest='incidentvulreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-e', '--eventlog', dest='eventreport', action='store_true', help='Event Log Report')
parser.add_argument('-x', '--xprotect', dest='impersonationreport', action='store_true', help='xProtect Log Report')
parser.add_argument('-r', '--resetstate', dest='resetstate', action='store_true', help='Reset State')
parser.add_argument('-mt', '--mitigationtime', dest='mitigationtime', action='store_true', help='mitigation time')
parser.add_argument('-cd', '--cleandata', dest='cleandata', action='store_true', help='cleandata') 
parser.add_argument('-u', '--updatestate', dest='updatestate', action='store_true', help='updatestate')
parser.add_argument('-uex', '--updateExternalScore', dest='updateExternalScore', action='store_true', help='updateExternalScore') 
parser.add_argument('--metabaseTempalateBackup', dest='metabaseTempalateBackup', action='store_true', help='metabaseTempalateBackup')
parser.add_argument('--metabaseTempalateReplace', dest='metabaseTempalateReplace', action='store_true', help='metabaseTempalateReplace') 
parser.add_argument('--createMBUser', dest='createMBUser', action='store_true')
parser.add_argument('-sd', '--start-date', dest='start_date', type=str, help='Start date for the report in YYYY-MM-DD format', default=None)
parser.add_argument('-ed', '--end-date', dest='end_date', type=str, help='End date for the report in YYYY-MM-DD format', default=None)
parser.add_argument('--version', action='version', version='1.0')
args = parser.parse_args()

# Get the Credentials

apikey = read_secret('api_key')
organization_domain = read_secret('dashboard_id')
urldashboard = f"https://{organization_domain}.vicarius.cloud"

#Initialization Postgresql
host = "appdb"
port = "5432"
user = read_secret('postgres_user')
password = read_secret('postgres_password')
database = read_secret('postgres_db')
optionalTools = read_secret('optional_tools')

substring = ","
if substring in optionalTools:
    tools = optionalTools.split(',')
else:
    tools = optionalTools
print("####################################")
print("####################################")
print("####################################")
print("Beginning a new Run")
print("####################################")
print("####################################")
print("####################################")

print (f"Dashboard URL is ", {urldashboard})


statepath = "/usr/src/app/reports/state.json"
if os.path.exists(statepath):
    print("Reading state.json from reports")
    dictState = state.getState()
else:
    print("copying state.json to reports ")
    srcpath = "/usr/src/app/scripts/state.json"
    shutil.copyfile(srcpath,statepath)
    print("Reading state.json from reports")
    dictState = state.getState()

#Version Check 
##get latest version 
#textpage = urlopen("https://www.w3.org/TR/PNG/iso_8859-1.txt")
#text = str(textpage.read(), 'utf-8')
#Get the Stats and Reports Names

def getAllEndpoitsTasks(fr0m,siz3,maxDate,minDate):
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000).isoformat()
    print("minDate->" + hmindate)
    print("maxDate->" + hmaxdate)
    """if lastdate == '0':
        head = "Taskid,AutomationId,AutomationName,endpointHash,Asset,TaskType,PublisherName,PathOrProduct,PathOrProductDesc,ActionStatus,MessageStatus,Username,CreateAt,UpdateAt\n"
        writeReport(dictState['reportNameEventsTasks'],head)"""
    
    control_rate (50)
    if maxDate is None:
        print("last date quireid")

    else:
        try:
            tasks_list,lastdate = tasks.getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,maxDate,minDate)
        except Exception as e:
            #print("lastdate= " + str(lastdate))
            print (f"An exception occurred: {e}")
            print(tasks_list,lastdate)
            tasks_list = ""
            #maxDate = str(lastdate)
            

    if len(tasks_list) > 0:
        #writeReport(dictState['reportNameEventsTasks'],strTasks)
        
        db.insert_into_table_tasks(tasks_list, host, port, user, password, database)
        
        maxDate = str(lastdate)

        #dictState.update({'lastEndpointsEventTask': lastdate})
        
        #state.setState(dictState)

        getAllEndpoitsTasks(fr0m,siz3,maxDate,minDate)
    else:
        print("No More Events")
      
def getAllEndpoits(fr0m,siz3,count,pbar):
    control_rate(20)

    try:
        strEndpoints,strEPStatus = assets.getEndpoints(apikey,urldashboard,fr0m,siz3)
    
    except Exception as e:
        strEndpoints = ""
        print (f"An exception occurred: {e}")
    
    if len(strEndpoints) > 0:

        db.insert_into_table_endpoints(strEndpoints,host,port,user,password,database)
        writeReport(dictState['reportAssets'],strEndpoints)
        db.insert_into_table_endpointsStatus(strEPStatus,host,port,user,password,database)
        pbar.update(siz3)
        
        #time.sleep(0.25)

        fr0m += siz3

    if fr0m < count:
        dictState.update({'lastEndpoints': fr0m})
        state.setState(dictState)
        control_rate(20)
        getAllEndpoits(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        dictState.update({'lastEndpoints': count})
        state.setState(dictState)     
        pbar.close()
        print("Done!")

def getAllEndpointsGroup(fr0m,siz3,count,endpointsGroups,endpointGroupsIds,endpointGroupsHashs,groupName,searchQuery):
    
    control_rate ()
    strEndpointGroups,strEndpointGroupsIds,strEndpointsGroupsHashs, = groups.getAssetsbySearchQuery(apikey,urldashboard,searchQuery,fr0m,siz3)
    endpointsGroups += strEndpointGroups 
    endpointGroupsIds += strEndpointGroupsIds 
    endpointGroupsHashs += strEndpointsGroupsHashs
    
  
    fr0m += siz3

    if fr0m < count:
        
        getAllEndpointsGroup(fr0m,siz3,count,endpointsGroups,endpointGroupsIds,endpointGroupsHashs,groupName,searchQuery)

    else:
        def remove_duplicates(endpoint_names, endpoint_ids, endpoint_hashs):
            unique_pairs = set()  # Usando um conjunto para rastrear pares únicos
            result_names = []
            result_ids = []
            result_hashs = []

            names = endpoint_names.split('|')
            ids = endpoint_ids.split('|')
            hashs = endpoint_hashs.split('|')

            for name, id, hash in zip(names, ids, hashs):
                pair = (name, id, hash)
                if pair not in unique_pairs:
                    unique_pairs.add(pair)
                    result_names.append(name)
                    result_ids.append(id)
                    result_hashs.append(hash)
            
            asset_names = '|'.join(result_names)
            asset_ids = '|'.join(result_ids)
            asset_hashs = '|'.join(result_hashs)

            return asset_names, asset_ids, asset_hashs
        
        result_names,result_ids,result_hashs = remove_duplicates(endpointsGroups,endpointGroupsIds,endpointGroupsHashs)
        
        #print(result_names)
        #print(result_ids)

        data_string = groupName + "," + result_names + "," + result_ids + "," + result_hashs + "\n"

        db.insert_into_table_groupendpoints(data_string, host, port, user, password, database)
            
        
        time.sleep(0.25)
 
def getAllGroupsSearchs(fr0m,siz3,count,endpointsGroups):
    control_rate ()
    strEndpointGroups = groups.getEndpointGroups(apikey,urldashboard,fr0m,siz3)
    endpointsGroups += strEndpointGroups
    #writeReport(dictState['reportAssetsGroup'],strEndpointGroups)
    
    
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllGroupsSearchs(fr0m,siz3,count,endpointsGroups)

    else:
        
        time.sleep(0.25)
        
        print("Done!")

        head = "groupname,assets,assetsids\n"
        writeReport(dictState['reportAssetsGroup'],head)

        db.check_create_table_groupendpoints(host, port, user, password, database)
        db.clean_table_groupendpoints(host, port, user, password, database)

        lstGps = endpointsGroups.split("\n")

        for gp in lstGps:
            
            lstGp = gp.split("||")
            
            if len(lstGp) > 1:
                groupName = lstGp[0]
                searchQuery = lstGp[1]
                groupscount = groups.getAssetsbySearchQueryCount(apikey,urldashboard,searchQuery)
                print(groupscount)

                fr0m = 0       
                
                if fr0m < groupscount:
                    endpointsGp = ""
                    endpointsGpId = ""
                    endpointGPHashs = ""
                    control_rate()                      
                    getAllEndpointsGroup(fr0m,siz3,groupscount,endpointsGp,endpointsGpId,endpointGPHashs,groupName,searchQuery)
                else:
                    print("Done!")

def getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,attribute,value\n"
        #writeReport(dictState['reportAssetsAttrributes'],head)
    
    control_rate()
    strEndpointsAttributes,epAttributeOBJ = assets.getEndpoitsExternalAttributes(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsAttrributes'],strEndpointsAttributes)
    db.insert_into_table_endpointsAttribute(epAttributeOBJ, host, port, user, password, database)
    pbar.update(siz3)
    #time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        #dictState.update({'lastEndpoints': fr0m})
        #state.setState(dictState)
        control_rate()
        getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllEndpoitsExploitabilityRiskFactors(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,riskfactorterm,riskfactordescription\n"
        #writeReport(dictState['reportAssetsExploitabilityRiskFactors'],head)
    
    strEndpointsExploitabilityRiskFactors,objEndpointsExploitabilityRiskFactors = assets.getEndpointScoresExploitabilityRiskFactors(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsExploitabilityRiskFactors'],strEndpointsAttributes)
    db.insert_into_table_endpointsExploitabilityRiskFactors(objEndpointsExploitabilityRiskFactors, host, port, user, password, database)
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpoitsExploitabilityRiskFactors(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllEndpoitsScoresImpactRiskFactors(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,riskfactorterm,riskfactorscore\n"
       # writeReport(dictState['reportAssetsScoresImpactRiskFactors'],head)

    strEndpointScoresImpactRiskFactors,objEndpointScoresImpactRiskFactors = assets.getEndpointScoresImpactRiskFactors(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsScoresImpactRiskFactors'],strEndpointsAttributes)
    db.insert_into_table_endpointsImpactFactors(objEndpointScoresImpactRiskFactors, host, port, user, password, database)
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpoitsScoresImpactRiskFactors(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate):
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    print("minDate->" + str(hmindate))
    print("maxDate->" + str(hmaxdate))

    time.sleep(3)

    jresponse = incidents.getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
   
    print(len(jresponse))
    if jresponse is None:
        print("jresponse é None, tentando novamente em 10 segundos...")
        time.sleep(10)
        getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)
        
    elif len(jresponse['serverResponseObject']) > 0:

        strEventsVuln,minDate = incidents.parseIncidentEventsbyType(jresponse)

        minDate = str(minDate)
        
        db.insert_into_table_incident(strEventsVuln, host, port, user, password, database)

        print("foi->" + str(len(jresponse['serverResponseObject'])))
        strEventsVuln = ""
        getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)
        
    else:
        print("No event")

def getAllIncidentEvents(fr0m,siz3,incidenttype,minDate,maxDate,table):
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    print("minDate->" + str(hmindate))
    print("maxDate->" + str(hmaxdate))

    time.sleep(3)
    gc.collect()
    jresponse = incidents.getEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
   

    if jresponse is None:
        print("jresponse é None, tentando novamente em 10 segundos...")
        time.sleep(10)
        getAllIncidentEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    elif len(jresponse['serverResponseObject']) > 0:

        strEventsVuln,minDate = incidents.parseEventsbyType(jresponse)

        minDate = str(minDate)
        if table == "incident":
            db.insert_into_table_incident(strEventsVuln, host, port, user, password, database)
        elif table == "events":
            db.insert_into_table_events(strEventsVuln, host, port, user, password, database)
        else:
            print("Table not found: getAllIncidentEvents")

        print("foi->" + str(len(jresponse['serverResponseObject'])))
        dictState.update({'minDateIncidentEventVulnerabilities': int(minDate)})
        state.setState(dictState)

        getAllIncidentEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    else:
        print("No event")

def getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table):
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    print("minDate->" + str(hmindate))
    print("maxDate->" + str(hmaxdate))

    time.sleep(3)

    jresponse = incidents.getxProtectEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
   

    if jresponse is None:
        print("jresponse é None, tentando novamente em 10 segundos...")
        time.sleep(10)
        getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    elif len(jresponse['serverResponseObject']) > 0:

        strEventsVuln,maxDate = incidents.parsexProtectEventsbyType(jresponse)

        maxDate = str(maxDate)
        if table == "incident":
            db.insert_into_table_incident(strEventsVuln, host, port, user, password, database)
        elif table == "events":
            db.insert_into_table_events(strEventsVuln, host, port, user, password, database)
        elif table == "xProtectEvents":
            db.insert_into_table_xProtectEvents(strEventsVuln, host, port, user, password, database)
        else:
            print("Table not found: getAllxProtectEvents")

        print("foi->" + str(len(jresponse['serverResponseObject'])))

        getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    else:
        print("No event")
    
def getAllEndpointsProductsVersions(fr0m,siz3,count,pbar):
   # if fr0m == 0:
        #head = "asset,productName,productRawEntryName,productVersion,publisherName,operatingSystemFamilyName,endpointId,productId\n"
       # writeReport(dictState['reportNameProducts'],head)

    strProductsVersions = products.getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportNameProducts'],strProductsVersions)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpointsProductsVersions(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
 
        pbar.close()
        print("Done!")

def getAppsPerRisk(fr0m,siz3):
    db.check_create_table_apps(host, port, user, password, database)
    db.clean_table_apps(host, port, user, password, database)

    lowRiskAppsCount,mediumRiskAppsCount,highRiskAppsCount = apprisk.getallApp(apikey,urldashboard)
    lrac = lowRiskAppsCount
    mrac = mediumRiskAppsCount
    hrac = highRiskAppsCount
    print(lowRiskAppsCount,mediumRiskAppsCount,highRiskAppsCount)
    # Sort counts 
    while lowRiskAppsCount > 500:
        siz3 = 500
        lowriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Low",fr0m,siz3)
        db.insert_into_table_apps(lowriskApps, host, port, user, password, database)
        print("500 Low Risk Apps Inserted")
        lowRiskAppsCount = lowRiskAppsCount - siz3
    siz3 = lowRiskAppsCount
    lowriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Low",fr0m,siz3)
    db.insert_into_table_apps(lowriskApps, host, port, user, password, database)
    print(str(lowRiskAppsCount) + " Low Risk Apps Inserted")

    while mediumRiskAppsCount > 500:
        siz3 = 500
        medriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Medium",fr0m,siz3)
        print("500 Medium Risk Apps Inserted")
        db.insert_into_table_apps(medriskApps, host, port, user, password, database)
        mediumRiskAppsCount = mediumRiskAppsCount - 500
    siz3 = mediumRiskAppsCount
    medriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Medium",fr0m,siz3)
    db.insert_into_table_apps(medriskApps, host, port, user, password, database)
    print(str(mediumRiskAppsCount) + " Medium Risk Apps Inserted")

    while highRiskAppsCount > 500:
        siz3 = 500
        highriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"High",fr0m,siz3)
        db.insert_into_table_apps(highriskApps, host, port, user, password, database)
        print("500 High Risk Apps Inserted")
        highRiskAppsCount = highRiskAppsCount - 500
    siz3 = highRiskAppsCount
    highriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"High",fr0m,siz3)
    db.insert_into_table_apps(highriskApps, host, port, user, password, database)
    print(str(highRiskAppsCount) + " High Risk Apps Inserted")

    totalAC = lrac + mrac + hrac
    print (str(totalAC) + " Apps inserted")

    #db.insert_into_table_apps

def ReportHasPatchApps():
    getAppsPerRisk(0,10)

def writeReport(reportName,strText):
    try:
        with open(reportName, 'a', encoding='UTF8') as report:
            report.write(strText)
        report.close()
    except:
        print("Somthing wrong with file")

def ReportTaskEvents(start_date=None, end_date=None):
    db.check_create_table_tasks(host, port, user, password, database)
    
    time.sleep(3)
    if start_date and end_date:
        try:
            maxDate = int (datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1000)
            minDate = int (datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1000)
        except ValueError as e:
            print(f"Invalid date format. Please use the format YYYY-MM-DD. Error: {e}")
            return
    else:
        dateNow = datetime.now()
        maxDate = str(int(dateNow.timestamp() * 1000))
        minDate = str(dictState['lastEndpointsEventTask'])
    
    dictState.update({'lastEndpointsEventTask': int(maxDate)})
    state.setState(dictState)

    fr0m = 0
    siz3 = 500 #Changed by Jordan from 100 

    #set these variables for specific event time interval

    #maxDate = str(1678737605066)
    #minDate = str(1659312000000)

    getAllEndpoitsTasks(fr0m,siz3,str(maxDate),str(minDate))

def ReportProdctsVersions():
    productscount = products.getCountEndpointPublisherProductVersions(apikey,urldashboard)
    print("Products -> " + str(productscount))
    fr0m = 0       
    
    if fr0m < productscount:
        deltacount = productscount - fr0m
        with tqdm(total=deltacount,desc="ProductsVersions") as pbar:
            
            getAllEndpointsProductsVersions(fr0m,500,productscount,pbar)
    else:
        print("Done!")

def ReportEndpoints():
    db.check_create_table_endpoints(host, port, user, password, database)
    db.clean_table_endpoints(host, port, user, password, database)
    
    head = "id,hostname,hash,alive,so,version,substatus,connectedbyproxy,tokengentime,deployed,last_connected,deploymentdate,lastcontactdate\n"
    writeReport(dictState['reportAssets'],head)
    
    control_rate(20)
    
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
   
    fr0m = 0
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:

            control_rate(20)
            getAllEndpoits(fr0m,500,endpointcount,pbar)
    else:
        print("Done!")

def ReportEndpointsAttributes():
    db.check_create_table_endpointsAttribute(host, port, user, password, database)
    db.clean_table_endpointsAttribute(host, port, user, password, database)
    endpointattribcount = assets.getEndpoitsExternalAttributesCount(apikey,urldashboard)
    #print("EndpointsAttribs -> " + str(endpointattribcount))
    fr0m = 0       
    
    if fr0m < endpointattribcount:
        deltacount = endpointattribcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:

            control_rate(20) 
            getAllEndpoitsExternalAttributes(fr0m,500,endpointattribcount,pbar)
    else:
        print("Done!")

def ReportEndpointScores():
    db.check_create_table_endpointsExploitabilityRiskFactors(host, port, user, password, database)
    db.check_create_table_endpointsImpactFactors(host, port, user, password, database)
    db.clean_table_endpointsExploitabilityRiskFactors(host, port, user, password, database)
    db.clean_table_endpointsImpactFactors(host, port, user, password, database)
    
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
    fr0m = 0       
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsScoresImpactRiskFactors(fr0m,500,endpointcount,pbar)
    else:
        print("Done!")

    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsExploitabilityRiskFactors(fr0m,500,endpointcount,pbar)
    else:
        print("Done!")    

def ReportIncident(start_date=None, end_date=None):

    # Constants
    INITIAL_MIN_DATE = int(datetime(2022, 1, 1).timestamp() * 1e9)  # Set the initial min date to January 1, 2022
    ONE_MONTH_NANOSECONDS = int(timedelta(days=30).total_seconds() * 1e9)  # Define the duration of one month in nanoseconds
    incident_type="MitigatedVulnerability,DetectedVulnerability"

    def process_in_chunks(minDate, maxDate, db, incident_type):
        current_min_date = minDate
        while current_min_date < maxDate:
            current_max_date = min(current_min_date + ONE_MONTH_NANOSECONDS, maxDate)
            try:
                control_rate(20)
                getAllIncidentEventVulnerabilities(0, 500, incident_type, str(current_min_date), str(current_max_date))
            except Exception as e:
                print(f"Error processing incidents: {e}")
            current_min_date = current_max_date

    def process_all_at_once(minDate, maxDate, db, incident_type):
        try:
            control_rate(20)
            getAllIncidentEventVulnerabilities(0, 500, incident_type, str(minDate), str(maxDate))
        except Exception as e:
            print(f"Error processing incidents: {e}")

    # Ensure the incident table exists in the database
    db.check_create_table_incident(host, port, user, password, database)
    
    if end_date:
        # Get the end date from the arguments
        try:
            maxDate = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1e9)
        except Exception as e:
            print(f"Invalid end date format. Please use the format YYYY-MM-DD. Error: {e} ")
            print (end_date)
            return
    else:
        # Get the current time in nanoseconds
        currentDate = datetime.now()
        maxDate = int(currentDate.timestamp() * 1e9)

    if start_date:
        # Get the start date from the arguments
        try:
            minDate = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1e9)
            print ("minDate set from args")
        except ValueError:
            print("Invalid start date format. Please use the format YYYY-MM-DD.")
            return
    else:
        # Load the most recent incident date from the database or use the initial date
        df = db.load_incident_to_df(host, port, user, password, database, maxDate)
        minDate = df['create_at_nano'].max() if df is not None and not df.empty else INITIAL_MIN_DATE
        print("minDate set from DB" if df is not df.empty else "minDate set from INITIAL_MIN_DATE")

    # Process incidents in monthly chunks if the interval is too large
    if (maxDate - minDate) > ONE_MONTH_NANOSECONDS:
        process_in_chunks(minDate, maxDate, db, incident_type)
    else:
        process_all_at_once(minDate, maxDate, db, incident_type)

def ReportIncidientImpersontation():
    db.check_create_table_xProtectEvents(host, port, user, password, database)
    dateNow = datetime.now()
    maxDate = str(int(float(dateNow.timestamp())*1000000000))
    minDate = str(dictState['minDatexProtectLog'])
    incidenttype = "ImpersonationAttempt" #Asset Events, App Events, User Events and System Events

    df = db.load_xProtectEvents_to_df(host, port, user, password, database, minDate)
    if df is not None:
        if df.empty:
            print("minDate Set from state.json")
        else:
            for ind in df.index:
                dbMinDate = df['create_at_nano'][ind]
            if dbMinDate > np.int64(minDate):
                minDate = str(dbMinDate)
                print("minDate Set from DB")
            else:
                print("minDate set from state.json")
    #print(maxDate)
    #print(type(maxDate))
    dictState.update({'minDatexProtectLog': int(maxDate)})
    state.setState(dictState)
    #print("Set max date")
    fr0m = 0
    siz3 = 500

    #set these variables for specific event time interval

    #maxDate = str(1697227198691126350)
    #minDate = str(1698796800000000000)

    getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,"xProtectEvents")

def ReportEventLog():
    db.check_create_table_Events(host, port, user, password, database)
    dateNow = datetime.now()
    maxDate = str(int(float(dateNow.timestamp())*1000000000))
    minDate = str(dictState['minDateEventLog'])
    incidenttype = "NewEndpoint,NewPublisherProduct,NewPublisherOperatingSystem,EndpointRemoved" #Asset Events, App Events, User Events and System Events

    df = db.load_Event_to_df(host, port, user, password, database, minDate)
    if df is not None:
        if df.empty:
            print("minDate Set from state.json")
        else:
            for ind in df.index:
                dbMinDate = df['create_at_nano'][ind]
            if dbMinDate > np.int64(minDate):
                minDate = str(dbMinDate)
                print("minDate Set from DB")
            else:
                print("minDate set from state.json")
    #print(maxDate)
    #print(type(maxDate))
    dictState.update({'minDateEventLog': int(maxDate)})
    state.setState(dictState)
    #print("Set max date")
    fr0m = 0
    siz3 = 500

    #set these variables for specific event time interval

    #maxDate = str(1697227198691126350)
    #minDate = str(1698796800000000000)

    getAllIncidentEvents(fr0m,siz3,incidenttype,minDate,maxDate,"events")

def SearchGroupsbyEndpoint(endpoint,dfg):
    # filter the dataframe to only include rows where the "assetname" column contains a certain string
    assetname_filter = dfg['assets'].str.contains(endpoint+'|',regex=False)
    df_filtered = dfg[assetname_filter]

    # extract the "groupname" column from the filtered dataframe
    groupname_series = df_filtered['groupname']

    # convert the groupname series to a list
    groupname_list = groupname_series.tolist()

    # create a string with groups
    my_string = "AllAssets|" + '|'.join(groupname_list)
    
    return my_string

def getAllEndpointsVulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash):

    try:
        control_rate()
        jresponse = vuln.getEndpointVulnerabilities(apikey, urldashboard, fr0m, siz3, minDate, maxDate, endpointName, endpointHash)

        server_response_count = jresponse.get('serverResponseCount', 0)

        if server_response_count > 0:
            strVulnerabilities, maxDate = vuln.parseEndpointVulnerabilities(apikey, urldashboard, jresponse)
            #print (strVulnerabilities)
            #print (strVulnerabilities)
            #writeReport(dictState['reportVulnerabilities'],strVulnerabilities)

            db.insert_into_table_activevulnerabilities(strVulnerabilities, host, port, user, password, database)

            if server_response_count >= siz3:
                getAllEndpointsVulnerabilities(fr0m, siz3, minDate, maxDate, endpointName, endpointHash)

    except Exception as e:
        # Handle errors/log here
        print (f"Exception ocurred at getAllEndpointsVulnerabilities: {e}")
        errorList.append("getAllEndpointsVulnerabilities:" + e)

def ReportVunerabilities():
   
    df = pd.read_csv(dictState['reportAssets'])
    df = df.sort_values(by='last_connected', ascending=False)
    df = df.drop_duplicates(subset=['hostname'], keep='first')
    print("Total Assets: " + str(len(df.index)))

    fr0m = 0
    siz3 = 500
    totalPatchs = 0    

    #head = "asset,assethash,productName,productRawEntryName,sensitivityLevelName,cve,vulnerabilityid,patchid,patchName,patchReleaseDate,createAt,updateAt,link,vulnerabilitySummary,V3BaseScore,V3ExploitabilityLevel,typecve,version,age\n"
    #writeReport(dictState['reportNameVulnerabilities'],head)

    db.check_create_table_activevulnerabilities(host, port, user, password, database)
    db.clean_table_activevulnerabilities(host, port, user, password, database)

      
    dateNow = datetime.now()
    minDate = 0000000000000
    maxDate = str(int(float(dateNow.timestamp())*1000))

    for ind in df.index:
        
        endpointName = df['hostname'][ind]
        endpointHash = df['hash'][ind]
        #endpointSO = df['so'][ind]
        getAllEndpointsVulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash)

def getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointHash):

    #Get the string of patchs by Patch and Write in Report
    strEndpointPatchs,tmpPatchs = patchs.getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointHash)
    print("patchsString->" + str(tmpPatchs))
    if len(strEndpointPatchs) > 0:
        db.insert_into_table_assetspatchs(strEndpointPatchs, host, port, user, password, database)

   
    if tmpPatchs >= siz3:
        fr0m += siz3
        getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointHash)
    
def ReportEndpointPatchs():

    table = "endpoints"

    df = db.load_table_to_df (host, port, user, password, database, table)
    
    #df = pd.read_csv(dictState['reportAssets'])

    df = df.drop_duplicates(subset=['endpoint_id'], keep='first')

    fr0m = 0
    siz3 = 500

    db.check_create_table_assetspatchs(host, port, user, password, database)
    db.clean_table_assetspatchs(host, port, user, password, database)

             
    for ind in df.index:        
        
        endpointName = df['endpoint_name'][ind]
        endpointSO = df['operating_system_name'][ind]
        endpointHash = df['endpoint_hash'][ind]
        #endpointGroups = SearchGroupsbyEndpoint(endpointName,dfg)
        getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointHash)

def ReportGroupsSearchs():
    control_rate(20)
    groupscount = groups.getEndpointGroupsCount(apikey,urldashboard)
    print("Endpoints Groups-> " + str(groupscount))
    fr0m = 0       
    
    if fr0m < groupscount:

        endpointsGroups = ""
                   
        getAllGroupsSearchs(fr0m,100,groupscount,endpointsGroups)
    else:
        print("Done!")
        if groupscount > 15:
            print("Endpoints and Groups Completed ")
            print("sleeping before tasks")
            time.sleep(60)
            print("starting tasks")

def resetState():
    """
    dictState.update({'lastEndpointVulnerabilities': 0})
    dictState.update({'lastEndpoints':0})
    dictState.update({'lastEndpointsEventTask':0})
    dictState.update({'lastProductVersions':0})
    dictState.update({'lastPatchsEndpoint':0})
    dictState.update({'minDateIncidentEventVulnerabilities':0}) #minDateIncidentEventVulnerabilities
    dictState.update({'lastIncidentEventVulnerabilities':0})
    dictState.update({'minDateEventLog':0})
    dictState.update({'minDatexProtectLog':0})   
    state.setState(dictState)
    print("Done!")
    """
    os.remove("/usr/src/app/reports/state.json")
    os.remove("/usr/src/app/reports/Endpoints.csv")
    os.remove("/usr/src/app/reports/EndpointsGroup.csv")

def updateState():
    lastEndpointsEventTask = cd.getLastEndpointsEventTask ()
    minDateIncidentEventVulnerabilities = cd.getLastIncidentEventVulnerabilities ()
    dictState.update({'lastEndpointVulnerabilities': 0})
    dictState.update({'lastEndpoints':0})
    dictState.update({'lastEndpointsEventTask': lastEndpointsEventTask})
    dictState.update({'lastProductVersions':0})
    dictState.update({'lastPatchsEndpoint':0})
    dictState.update({'minDateIncidentEventVulnerabilities': minDateIncidentEventVulnerabilities}) #minDateIncidentEventVulnerabilities
    dictState.update({'lastIncidentEventVulnerabilities':0})    
    state.setState(dictState)
    print("Done!")

def logscriptActivity(startTime,endTime,errorList):
    db.check_create_table_scriptActivity(host, port, user, password, database)

    if len(errorList) > 0:
        for row in errorList:
            #startTime = startTime.isoformat()
            #endTime = endTime.isoformat()
            recordjson = {
                "starttime": startTime,
                "endtime": endTime,
                "errors": str(row)
            }

            db.insert_into_table_scriptActivity(recordjson,host,port,user,password,database)
    else:
        startTime = startTime.isoformat()
        endTime = endTime.isoformat()
        recordjson = {
            "starttime": startTime,
            "endtime": endTime,
            "errors": "No Errors"
        }
        db.insert_into_table_scriptActivity(recordjson,host,port,user,password,database) 

def configoptionalTools(host,port,user,password,tools):
    import optionalDBConnectors as optionalDB
    if "metabase" in tools:
        print("Using Tool: Metabase")
        dbexisted = optionalDB.create_db_metabase(host, port, user, password)
        if dbexisted == False:
            print("Metabase Database required")
            optionalDB.create_user_metabase(host, port, user, password)
            optionalDB.restore_database(host,port)
        else:
            print("Metabase Database already exists")
    """
    if "n8n" in tools:
        dbexisted = optionalDB.create_db_n8n(host, port, user, password)
        if dbexisted == False:
            print("n8n Database created")
        else:
            print("n8n Database already exists")
    """
    #db.create_db_n8n(host, port, user, password)

def dbreset():
    #Reset all states 
    resetState()
    #Drop all tables 
    db.drop_all_tables(host, port, user, password, database)

def backupMetabaseTemplate(host,port):
    import optionalDBConnectors as optionalDB
    optionalDB.back_postgresDB(host,port)

def metabaseTempalateReplace(host,port,user,password,tools):
    import optionalDBConnectors as optionalDB
    print("Dropping DB")
    optionalDB.drop_metabase_db(host,port,user,password)
    print("configuring DB")
    configoptionalTools(host, port, user, password, tools)


def main():
    args.dashboard
    startTime = datetime.now()
    print("Script start time: " + str(startTime))    
    errorList = []
    print("Starting VickyTopia Report CLI")
    lastrun = dictState['vRxLastRun']
    vRxSetup = dictState['vRxSetup']
    print('Last run: ' + str(lastrun))
    print('vRxReportsSetup: ' + str(vRxSetup))
    if args.resetstate:
        dbreset()
        resetState()
        exit()
    if args.metabaseTempalateReplace:
        print("Replacing Metabase Template ")
        metabaseTempalateReplace(host, port, user, password, tools)
        print("Metabase Template is up to date ")
        exit()
    if vRxSetup == 0:
        now = datetime.now()
        m6 = now - relativedelta(months=6)
        date_str = m6.strftime("%Y-%m-%d")
        start_date = date_str
        end_date = now.strftime("%Y-%m-%d")
        print('Reports dashboard has not been setup. Completing the initial run!')
        BeginRun = datetime.now()
        print("Pulling Data Start Time: " + str(BeginRun))

        print("Query Start date: " + str(start_date))
        print("Query End date: " + str(end_date))
        #Reset Database 

        #Setup Database
        db.check_create_database(host, port, user, password, database)
        cd.remove_all_except()

        try:
            ReportEndpoints()
        except Exception as e:           
            errorList.append("ReportEndpoints:" + e)
            print(str(e))

        try:
            ReportGroupsSearchs()
        except Exception as e:
            errorList.append("ReportGroupsSearchs:" + str(e))
            print(str(e))
        try:
            ReportTaskEvents(start_date, end_date)
        except Exception as e:
            errorList.append("ReportTaskEvents:" + str(e))
            print(str(e))

        try:
            ReportVunerabilities()
        except Exception as e:
            errorList.append("ReportVunerabilities:" + str(e))
            print(str(e))
        
        try:
            ReportEndpointPatchs()
        except Exception as e:
            errorList.append("ReportEndpointPatchs:" + str(e))
            print(str(e))

        try:
            ReportIncident(start_date, end_date)
        except Exception as e:
            errorList.append("ReportIncident:" + str(e))
            print(str(e))  
        try:
            ReportHasPatchApps()          
        except Exception as e:
            errorList.append("ReportHasPatchApps:" + str(e))
            print(str(e)) 

        
        EndRun = datetime.now()
        print("Initial Run Completed: " + str(EndRun))
        dictState.update({'vRxSetup': 1})
        state.setState(dictState)
    else:
        startTime = datetime.now()

        print("Script start time: " + str(startTime))
        if args.allreports:
            
            # print current timestamp as script start time
            startTime = datetime.now()
            print("Script start time: " + str(startTime))
            
            db.check_create_database(host, port, user, password, database)
            cd.remove_all_except()

            try:
                ReportEndpoints()
            except Exception as e:           
                errorList.append("ReportEndpoints:" + e)
                print(str(e))

            try:
                ReportGroupsSearchs()
            except Exception as e:
                errorList.append("ReportGroupsSearchs:" + str(e))
                print(str(e))
            try:
                ReportTaskEvents()
            except Exception as e:
                errorList.append("ReportTaskEvents:" + str(e))
                print(str(e))

            try:
                ReportVunerabilities()
            except Exception as e:
                errorList.append("ReportVunerabilities:" + str(e))
                print(str(e))
            
            try:
                ReportEndpointPatchs()
            except Exception as e:
                errorList.append("ReportEndpointPatchs:" + str(e))
                print(str(e))

            try:
                ReportIncident()
            except Exception as e:
                errorList.append("ReportIncident:" + str(e))
                print(str(e))  
            try:
                ReportHasPatchApps()          
            except Exception as e:
                errorList.append("ReportHasPatchApps:" + str(e))
                print(str(e)) 
            #cd.cleanData()
            #mt.get_mitigation_time()
            
        elif args.assetsreport:
            ReportEndpoints()
            ReportEndpointsAttributes()
            ReportEndpointScores()        
            #ReportGroupsAtrributesTags()
            ReportGroupsSearchs()

        elif args.tasksreport:
            if args.start_date and args.end_date:
                ReportTaskEvents(args.start_date, args.end_date)
            else:
                ReportTaskEvents()

        elif args.vulnreport:
            ReportVunerabilities()        

        elif args.patchsreport:
            ReportEndpointPatchs()

        elif args.incidentvulreport:
            if args.start_date and args.end_date:
                ReportIncident(args.start_date, args.end_date)
            else:
                ReportIncident()

        elif args.eventreport:
            ReportEventLog()

        elif args.impersonationreport:
            ReportIncidientImpersontation()
    
        elif args.hasPatchAppsreport:
            ReportHasPatchApps()
   
        elif args.resetstate:
            dbreset()
            resetState()
            exit()
   
        elif args.mitigationtime:
            mt.get_mitigation_time()
        
        elif args.cleandata:
            cd.cleanData()
        
        elif args.updatestate:
            updateState ()
        
        elif args.updateExternalScore:
            updExSc.download_and_load_epss_data (host, port, user, password, database)
        
        elif args.metabaseTempalateBackup:
            print("Backing up Metabase Template")
            print("Option is Disabled")
            backupMetabaseTemplate(host, port)

        elif args.createMBUser:
            import optionalDBConnectors as optionalDB
            print("Creating Metabase User")
            print("Option is Disabled")
            optionalDB.create_user_metabase(host, port, user, password)
        else:
            print("Select one report and try again!!!")
    
    endTime =  datetime.now()

    dictState.update({'vRxLastRun': str(endTime)})
    state.setState(dictState)
    print("Script Run completed")
    print("Setting Optional Tools")
    #create Views
    db.create_table_views(host, port, user, password, database)
    #configure optional Tools
    configoptionalTools(host, port, user, password, tools)
    print("Script end time: " + str(endTime))
    print("Script Error List:" + str(errorList))
    logscriptActivity(startTime,endTime,errorList)

    print("***********************************")
    print("End of Run ")
    print("***********************************")
if __name__ == '__main__':
    main()



