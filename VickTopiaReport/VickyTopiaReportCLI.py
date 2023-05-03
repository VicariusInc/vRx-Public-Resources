#Author: Joaldir Rani

import argparse
from tqdm import tqdm
import time
import pandas as pd

import json

import VickyState as state
import EndpointsEventTask as tasks
import EndpointVulnerabilities as vuln
import Endpoint as assets
import PatchsByAssets as patchs
import EndpointPublisherProductVersions as products
import IncidentsEvents as incidents
import EndpointGroups as groups
from datetime import datetime, timedelta


parser = argparse.ArgumentParser(description='Args for VikyTopiaReport')
parser.add_argument('-k', '--api-key', dest='apiKey', action='store', required=True, help='Topia API key')
parser.add_argument('-d', '--dashboard', dest='dashboard', action='store', required=True, help='Url dashboard ex. https://xxxx.vicarius.cloud')
parser.add_argument('--allreports', dest='allreports', action='store_true', help='All Reports')
parser.add_argument('-a', '--assetsreport', dest='assetsreport', action='store_true', help='Assets Reports')
parser.add_argument('-t', '--taskreport', dest='tasksreport', action='store_true', help='Task Reports')
parser.add_argument('-v', '--vulnerabilitiesreport', dest='vulnreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-p', '--patchsreport', dest='patchsreport', action='store_true', help='Patchs Versions Reports')
parser.add_argument('-i', '--incidentvulnerability', dest='incidentvulreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-r', '--resetstate', dest='resetstate', action='store_true', help='Reset State')

parser.add_argument('--version', action='version', version='1.0')

args = parser.parse_args()

# Get the Credentials
apikey = args.apiKey
urldashboard = args.dashboard

#Get the Stats and Reports Names
dictState = state.getState()

def getAllEndpoitsTasks(fr0m,siz3,count,pbar,lastdate):
    if lastdate == '0':
        head = "Taskid,AutomationId,AutomationName,Asset,TaskType,PublisherName,PathOrProduct,PathOrProductDesc,ActionStatus,MessageStatus,Username,CreateAt,UpdateAt\n"
        writeReport(dictState['reportNameEventsTasks'],head)
    
    strTasks,lastdate = tasks.getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,lastdate)
    
    writeReport(dictState['reportNameEventsTasks'],strTasks)    
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3
      
    if fr0m < count:        
        dictState.update({'lastEndpointsEventTask': lastdate})
        state.setState(dictState)
        getAllEndpoitsTasks(fr0m,siz3,count,pbar,lastdate)

    else:
        pbar.update(count)
        time.sleep(0.25)

        dictState.update({'lastEndpointsEventTask': lastdate})
        state.setState(dictState)
        pbar.close()
        print("Done!")

def getAllEndpoits(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "ID,HOSTNAME,HASH,SO,VERSION,endpointUpdatedAt\n"
        writeReport(dictState['reportAssets'],head)

    strEndpoints = assets.getEndpoints(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportAssets'],strEndpoints)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        dictState.update({'lastEndpoints': fr0m})
        state.setState(dictState)
        getAllEndpoits(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        dictState.update({'lastEndpoints': count})
        state.setState(dictState)     
        pbar.close()
        print("Done!")

def getAllEndpointsGroup(fr0m,siz3,count,pbar,endpointsGroups,groupName,searchQuery):
    
    strEndpointGroups = groups.getAssetsbySearchQuery(apikey,urldashboard,searchQuery,fr0m,siz3)
    endpointsGroups += strEndpointGroups 
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpointsGroup(fr0m,siz3,count,pbar,endpointsGroups,groupName,searchQuery)

    else:
        writeReport(dictState['reportAssetsGroup'],groupName + "," + endpointsGroups + "\n")
        
        pbar.update(siz3)
        time.sleep(0.25)
        pbar.close()
 
    

def getAllGroupsSearchs(fr0m,siz3,count,pbar,endpointsGroups):
    strEndpointGroups = groups.getEndpointGroups(apikey,urldashboard,fr0m,siz3)
    endpointsGroups += strEndpointGroups
    #writeReport(dictState['reportAssetsGroup'],strEndpointGroups)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllGroupsSearchs(fr0m,siz3,count,pbar,endpointsGroups)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        pbar.close()
        print("Done!")
    
        # Obtain Asssets From GroupSearch
        head = "groupname,assets\n"
        writeReport(dictState['reportAssetsGroup'],head)

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
                    with tqdm(total=groupscount,desc=groupName) as pbar:            
                        getAllEndpointsGroup(fr0m,siz3,groupscount,pbar,endpointsGp,groupName,searchQuery)
                else:
                    print("Done!")

def getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "id,asset,attribute,value\n"
        writeReport(dictState['reportAssetsAttrributes'],head)

    strEndpointsAttributes = assets.getEndpoitsExternalAttributes(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportAssetsAttrributes'],strEndpointsAttributes)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        #dictState.update({'lastEndpoints': fr0m})
        #state.setState(dictState)
        getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllEndpoitsExploitabilityRiskFactors(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "id,asset,riskfactorterm,riskfactordescription\n"
        writeReport(dictState['reportAssetsExploitabilityRiskFactors'],head)

    strEndpointsAttributes = assets.getEndpointScoresExploitabilityRiskFactors(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportAssetsExploitabilityRiskFactors'],strEndpointsAttributes)
    
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
    if fr0m == 0:
        head = "id,asset,riskfactorterm,riskfactorscore\n"
        writeReport(dictState['reportAssetsScoresImpactRiskFactors'],head)

    strEndpointsAttributes = assets.getEndpointScoresImpactRiskFactors(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportAssetsScoresImpactRiskFactors'],strEndpointsAttributes)
    
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
    print("minDate->"+minDate)
    print("maxDate->"+maxDate)

    """
    if int(minDate) == 0:
        head = "assetid,asset,cve,severity,eventType,publisher,apporso,threatLevelId,vulV3exploitlevel,vulv3basescore,patchId,vulsummary,eventcreatedat,eventupdatedat\n"
        writeReport(dictState['reporIncidentEventVulnerabilities'],head)
    """

    jresponse = incidents.getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
    
    if len(jresponse['serverResponseObject']) > 0:
        strEventsVuln,maxDate = incidents.parseIncidentEventsbyType(jresponse)
        maxDate = str(maxDate)
        
        writeReport(dictState['reporIncidentEventVulnerabilities'],strEventsVuln)
        print("foi->" + str(len(jresponse['serverResponseObject'])))
        getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)
        
    else:
        print("No event")
    
def getAllEndpointsProductsVersions(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "asset,productName,productRawEntryName,productVersion,publisherName,operatingSystemFamilyName,endpointId,productId\n"
        writeReport(dictState['reportNameProducts'],head)

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

def writeReport(reportName,strText):
    try:
        with open(reportName, 'a', encoding='UTF8') as report:
            report.write(strText)
        report.close()
    except:
        print("Somthing wrong with file")

def ReportTaskEvents():
    lastdate = str(dictState['lastEndpointsEventTask'])
    taskcount = tasks.getCountEvents(apikey,urldashboard,lastdate)
    print("Tasks -> " + str(taskcount))
    
    fr0m = 0
    if fr0m < taskcount:
        with tqdm(total=taskcount,desc="Tasks") as pbar:
            getAllEndpoitsTasks(fr0m,1000,taskcount,pbar,lastdate)
    else:
        print("Done!")

def ReportProdctsVersions():
    productscount = products.getCountEndpointPublisherProductVersions(apikey,urldashboard)
    print("Products -> " + str(productscount))
    fr0m = 0       
    
    if fr0m < productscount:
        deltacount = productscount - fr0m
        with tqdm(total=deltacount,desc="ProductsVersions") as pbar:
            
            getAllEndpointsProductsVersions(fr0m,1000,productscount,pbar)
    else:
        print("Done!")

def ReportEndpoints():
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
    fr0m = 0
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:
            
            getAllEndpoits(fr0m,300,endpointcount,pbar)
    else:
        print("Done!")

def ReportEndpointsAttributes():
    endpointattribcount = assets.getEndpoitsExternalAttributesCount(apikey,urldashboard)
    #print("EndpointsAttribs -> " + str(endpointattribcount))
    fr0m = 0       
    
    if fr0m < endpointattribcount:
        deltacount = endpointattribcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:
            
            getAllEndpoitsExternalAttributes(fr0m,1000,endpointattribcount,pbar)
    else:
        print("Done!")

def ReportEndpointScores():
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
    fr0m = 0       
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsScoresImpactRiskFactors(fr0m,100,endpointcount,pbar)
    else:
        print("Done!")

    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsExploitabilityRiskFactors(fr0m,100,endpointcount,pbar)
    else:
        print("Done!")    

def ReportIncident():

    dateNow = datetime.now()
    maxDate = str(int(float(dateNow.timestamp())*1000000000))
    minDate = str(dictState['minDateIncidentEventVulnerabilities'])
    incidenttype = "MitigatedVulnerability,DetectedVulnerability"

    dictState.update({'minDateIncidentEventVulnerabilities': int(maxDate)})
    state.setState(dictState)

    fr0m = 0
    siz3 = 500

    #maxDate = str(1673976925258800423)
    #minDate = str(1672542000000000000)

    getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)

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

def getAllEndpointsVulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash,endpointGroups):
    
    jresponse = vuln.getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)

    if jresponse['serverResponseCount'] > 0:

        strVulnerabilities,maxDate = vuln.parseEndpointVulnerabilities(jresponse,endpointGroups)
        writeReport(dictState['reportNameVulnerabilities'],strVulnerabilities)
        
        if jresponse['serverResponseCount'] >= siz3:
            getAllEndpointsVulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash,endpointGroups)    
   
    
def ReportVunerabilities():
   
    df = pd.read_csv(dictState['reportAssets'])
    print(len(df.index))

    df = df.sort_values(by='endpointUpdatedAt', ascending=False)

    df = df.drop_duplicates(subset=['HOSTNAME'], keep='first')
    print(len(df.index))

    dfg = pd.read_csv(dictState['reportEndpointGroups'])

    fr0m = 0
    siz3 = 300
    totalPatchs = 0

    head = "asset,assethash,group,productName,productRawEntryName,sensitivityLevelName,cve,vulnerabilityid,patchid,patchName,patchReleaseDate,createAt,updateAt,link,vulnerabilitySummary,V3BaseScore,V3ExploitabilityLevel\n"
    writeReport(dictState['reportNameVulnerabilities'],head)

    with tqdm(total=len(df.index),desc="Endpoint Pa") as pbar:  
        print()
        dateNow = datetime.now()

        minDate = 0000000000000
        maxDate = str(int(float(dateNow.timestamp())*1000))

        for ind in df.index:
            pbar.update()
            endpointName = df['HOSTNAME'][ind]
            endpointHash = df['HASH'][ind]
            endpointSO = df['SO'][ind]            
            endpointGroups = SearchGroupsbyEndpoint(endpointName,dfg)

            getAllEndpointsVulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash,endpointGroups)
        pbar.close()

def getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointGroups,totalPatchs):

    #Get the string of patchs by Patch and Write in Report
    strEndpointPatchs,tmpPatchs = patchs.getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointGroups)

    totalPatchs += tmpPatchs

    if len(strEndpointPatchs) > 0:
        writeReport(dictState['reportNameEndpointPatchs'],strEndpointPatchs)        
    
    if tmpPatchs >= siz3:
        fr0m += siz3
        getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointGroups,totalPatchs)
    
    else:
        strcountendpointpatchs = endpointName + "," + str(totalPatchs) + "\n"
        writeReport(dictState['reportCountEndpointPatchs'],strcountendpointpatchs)


def ReportEndpointPatchs():
    # get the assets
    df = pd.read_csv(dictState['reportAssets'])
    #dduplication hostname
    df = df.drop_duplicates(subset=['HOSTNAME'], keep='first')

    # get Groups
    dfg = pd.read_csv(dictState['reportEndpointGroups'])

    fr0m = 0
    siz3 = 100
    totalPatchs = 0

    strcountendpointpatchs = "Asset,TotalPactchs\n"
    writeReport(dictState['reportCountEndpointPatchs'],strcountendpointpatchs)

    strEndpointPatchs = "Asset,Group,SO,PatchName,SeverityLevel,SeverityName,Description,PatchID\n"
    writeReport(dictState['reportNameEndpointPatchs'],strEndpointPatchs)

    with tqdm(total=len(df.index),desc="Endpoint Pacths") as pbar:            
        for ind in df.index:
            pbar.update()
            endpointHash = df['HASH'][ind]
            endpointName = df['HOSTNAME'][ind]
            endpointSO = df['SO'][ind]            
            endpointGroups = SearchGroupsbyEndpoint(endpointName,dfg)
            getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointGroups,totalPatchs)

        pbar.close()

def ReportGroupsSearchs():
    groupscount = groups.getEndpointGroupsCount(apikey,urldashboard)
    print("Endpoints Groups-> " + str(groupscount))
    fr0m = 0       
    
    if fr0m < groupscount:

        endpointsGroups = ""
        with tqdm(total=groupscount,desc="EndpointGroups") as pbar:            
            getAllGroupsSearchs(fr0m,10,groupscount,pbar,endpointsGroups)
    else:
        print("Done!")
  

def resetState():
    dictState.update({'lastEndpointVulnerabilities': 0})
    dictState.update({'lastEndpoints':0})
    dictState.update({'lastEndpointsEventTask':0})
    dictState.update({'lastProductVersions':0})
    dictState.update({'lastPatchsEndpoint':0})
    dictState.update({'lastCVEsEndpoint':0})
    dictState.update({'lastIncidentEventVulnerabilities':0})    
    state.setState(dictState)
    print("Done!")

def main():    
    if args.allreports:
        ReportTaskEvents()
        ReportVunerabilities()
        ReportEndpoints()
        ReportGroupsSearchs()
    
    elif args.assetsreport:
        ReportEndpoints()
        #ReportEndpointsAttributes()
        #ReportEndpointScores()        
        #ReportGroupsAtrributesTags()
        ReportGroupsSearchs()
    
    elif args.tasksreport:
        ReportTaskEvents()

    elif args.vulnreport:
        ReportVunerabilities()        

    elif args.patchsreport:
        ReportEndpointPatchs()

    elif args.incidentvulreport:
        ReportIncident()
   
    elif args.resetstate:
        resetState()

    else:
        print("Select one report and try again!!!")

if __name__ == '__main__':
    main()




