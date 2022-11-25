
#Author: Joaldir Rani

import argparse
from tqdm import tqdm
import time
import pandas as pd

import VickyState as state
import EndpointsEventTask as tasks
import EndpointVulnerabilities as vuln
import Endpoint as assets
import PatchsByAssets as patchs
import EndpointPublisherProductVersions as products
import IncidentsEvents as incidents


parser = argparse.ArgumentParser(description='Args for VikyTopiaReport')
parser.add_argument('-k', '--api-key', dest='apiKey', action='store', required=True, help='Topia API key')
parser.add_argument('-d', '--dashboard', dest='dashboard', action='store', required=True, help='Url dashboard ex. https://xxxx.vicarius.cloud')
parser.add_argument('--allreports', dest='allreports', action='store_true', help='All Reports')
parser.add_argument('-a', '--assetsreport', dest='assetsreport', action='store_true', help='Assets Reports')
parser.add_argument('-t', '--taskreport', dest='tasksreport', action='store_true', help='Task Reports')
parser.add_argument('-v', '--vulnerabilitiesreport', dest='vulnreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-p', '--patchsreport', dest='patchsreport', action='store_true', help='Patchs Versions Reports')
parser.add_argument('-i', '--incidentvulnerability', dest='incidentvulreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('--topiavsnessusCVEs', dest='topiavsnessus', action='store_true', help='Compare Nessus CVE list in csv')
parser.add_argument('--nessuscsv', dest='nessuscve', action='store', help='Nessus Reports CVE required for --topiavsnessusCVE')
parser.add_argument('--excel', dest='excel', action='store_true', help='Excel Report')

parser.add_argument('--version', action='version', version='1.0')

args = parser.parse_args()

# Get the Credentials
apikey = args.apiKey
urldashboard = args.dashboard

#Get the Stats and Reports Names
dictState = state.getState()

def getAllEndpoitsTasks(fr0m,siz3,count,pbar,lastdate):
    if lastdate == 0:
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

def getAllEndpoitsVulnerabilities(fr0m,siz3,count,pbar,lastdate):
    if lastdate == 0:
        head = "asset,productName,productRawEntryName,sensitivityLevelName,cve,patchid,patchName,patchReleaseDate,createAt,updateAt,link,vulnerabilitySummary\n"
        writeReport(dictState['reportNameVulnerabilities'],head)
    
    strVulnerabilities,lastdate = vuln.getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,lastdate)
    writeReport(dictState['reportNameVulnerabilities'],strVulnerabilities)
   
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3   
    
    if fr0m < count:
        dictState.update({'lastEndpointVulnerabilities': lastdate})
        state.setState(dictState)
        getAllEndpoitsVulnerabilities(fr0m,siz3,count,pbar,lastdate)

    else:
        pbar.update(count)
        time.sleep(0.25)

        dictState.update({'lastEndpointVulnerabilities': lastdate})
        state.setState(dictState)
        pbar.close()
        print("Done!")

def getAllEndpoits(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "ID,HOSTNAME,HASH,SO\n"
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

def getAllEndpoitsGroups(fr0m,siz3,count,pbar):
    if fr0m == 0:
        head = "group,attribute,value\n"
        writeReport(dictState['reportAssetsGroup'],head)

    strEndpointGroups = assets.getEndpointGroups(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportAssetsGroup'],strEndpointGroups)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        #dictState.update({'lastEndpoints': fr0m})
        #state.setState(dictState)
        getAllEndpoitsGroups(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        #dictState.update({'lastEndpoints': count})
        #state.setState(dictState)     
        pbar.close()
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

def getAllIncidentEventVulnerabilities(fr0m,siz3,count,pbar,incidenttype,lastdate):
    if int(lastdate) == 0:
        head = "asset,cve,severity,eventType,publisher,apporso,threatLevelId,vulV3exploitlevel,vulv3basescore,patchId,vulsummary,eventcreatedat,eventupdatedat\n"
        writeReport(dictState['reporIncidentEventVulnerabilities'],head)

    strEventsVuln,lastdate = incidents.getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,lastdate)
    writeReport(dictState['reporIncidentEventVulnerabilities'],strEventsVuln)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        dictState.update({'lastIncidentEventVulnerabilities': int(lastdate)})
        state.setState(dictState)
        lastdate = str(lastdate)
        getAllIncidentEventVulnerabilities(fr0m,siz3,count,pbar,incidenttype,lastdate)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        dictState.update({'lastIncidentEventVulnerabilities': int(lastdate)})
        lastdate = int(lastdate)
        state.setState(dictState)     
        pbar.close()
        print("Done!")

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

def getAllPatchsEndpoint(fr0m,siz3,count,endpointHash,endpointName,pbar):
    strPatchEnpoints = patchs.getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointHash,endpointName)
    writeReport(dictState['reportNameEndpointPatchs'],strPatchEnpoints)

    pbar.update(siz3)
    time.sleep(0.25)
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllPatchsEndpoint(fr0m,siz3,count,endpointHash,endpointName)

    else:
        pbar.update(siz3)
        time.sleep(0.25)

        pbar.close()
        print("Done!")

def getAllCVEsbyEndpointName(fr0m,siz3,count,endpointName,lstCVEs):
    lstTempCVEs = vuln.getCVEsbyEndpointName(apikey,urldashboard,fr0m,siz3,endpointName)
    lstCVEs = lstCVEs + lstTempCVEs

    fr0m += siz3   
    
    if fr0m < count:
        getAllCVEsbyEndpointName(fr0m,siz3,count,endpointName,lstCVEs)

    else:
        print("FIM")
    
    return lstCVEs

def dduplist(lst):
    lst = list(dict.fromkeys(lst))
    return lst

def writeReport(reportName,strText):
    try:
        with open(reportName, 'a', encoding='UTF8') as report:
            report.write(strText)
        report.close()
    except:
        print("Somthing wrong with file")

def generateExcel(reportstogen):

    for reporttogen in reportstogen:

        df = pd.read_csv(reporttogen)
        
        excel_file = (str(reporttogen).replace(".csv",".xlsx")) #'TopiaReport.xlsx'
        
        #print(str(reporttogen).replace(".csv",""))

        namesheet = str(reporttogen).replace(".csv","")
        namesheet = namesheet.replace("reports\\","")

        sheet_name = (str(reporttogen).replace(".csv",""))
        sheet_name = namesheet.replace("reports\\","")
        sheet_name = sheet_name[0:30] #'vulnerabilities'

        writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')
        df.to_excel(writer, sheet_name=sheet_name, startrow=7, header=False, index=False)
        #workbook  = writer.book
        worksheet = writer.sheets[sheet_name]
        # Get the dimensions of the dataframe.
        (max_row, max_col) = df.shape
        # Create a list of column headers, to use in add_table().
        column_settings = [{'header': column} for column in df.columns]
        # Add the Excel table structure. Pandas will add the data.
        # 6 = pula 7 linhas
        startrow = 6
        max_row = max_row + startrow

        worksheet.add_table(startrow, 0, max_row, max_col - 1, {'columns': column_settings})
        # Make the columns wider for clarity.
        worksheet.set_column(0, max_col - 1, 12)
        
    writer.save()
    
    

def generateExcelTopiaNessus():
    dftask = pd.read_csv(dictState['reportNameEventsTasks'])
    print(dftask)
    excel_file = 'TopiaReport.xlsx'
    sheet_name = 'Task Status'

    writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')
    dftask.to_excel(writer, sheet_name=sheet_name, startrow=7, header=False, index=False)
    workbook  = writer.book
    worksheet = writer.sheets[sheet_name]
    # Get the dimensions of the dataframe.
    (max_row, max_col) = dftask.shape
    # Create a list of column headers, to use in add_table().
    column_settings = [{'header': column} for column in dftask.columns]
    # Add the Excel table structure. Pandas will add the data.
    # 6 = pula 7 linhas
    startrow = 6
    max_row = max_row + startrow

    worksheet.add_table(startrow, 0, max_row, max_col - 1, {'columns': column_settings})
    # Make the columns wider for clarity.
    worksheet.set_column(0, max_col - 1, 12)
    writer.save()

def getEnpointsNameDdupNessus(reportNessusName):
    lstEndpointName = []
    with open(reportNessusName) as f:
        while True:
            line = f.readline()
            
            if not line:
                break

            line = line.strip()
            strCVE = line.split(";")        

            endpointName = strCVE[1]            
            endpointName = endpointName.upper()

            lstEndpointName.append(endpointName)
    
    #ddup

    lstEndpointName = dduplist(lstEndpointName)
    #sort
    lstEndpointName.sort()

    return lstEndpointName

def getNessesCVEsbyEndpointName(endpointName,reportNessusName):
    
    lstNessesCVEsbyEndpointName = []

    with open(reportNessusName) as f:
        while True:
            line = f.readline()
            if not line:
                break

            line = line.strip()
            strCVE = line.split(";")

            endpointNameNessus = strCVE[1]
            endpointNameNessus = endpointNameNessus.upper()

            if endpointName == endpointNameNessus:

                cves = strCVE[0].replace("\"","").split(",")

                for cve in cves:
                    lstNessesCVEsbyEndpointName.append(cve)                    
    
    return lstNessesCVEsbyEndpointName


def getReportTopiaNessus(lstEndpointName,reportNessusName):
    strReportTopiaNessus = "HOSTNAME,NESSUS_CVES,TOPIA_CVES,PRODUCTNAME,LINK,PATCHID,PATCHNAME,PATCHRELEASE\n"
    
    for endpointName in lstEndpointName:
        
        #obten lista de CVES nessus
        lstNessusCves = getNessesCVEsbyEndpointName(endpointName,reportNessusName)
        lstNessusCves = dduplist(lstNessusCves)

        #obten lista de CVES topia
        lstTopiaCVES = []
        cvecount = vuln.getCountCVEs(apikey,urldashboard,endpointName)
        
        #comparaNessus
        if cvecount == 0:
            lstTopiaCVES = []
        else:
            lstTopiaCVES = getAllCVEsbyEndpointName(0,500,cvecount,endpointName,lstTopiaCVES)
            lstTopiaCVES = dduplist(lstTopiaCVES)


            for nessusCve in lstNessusCves:
                topiaHit = False

                for topiaCveProduct in lstTopiaCVES:
                    #print(topiaCveProduct)
                    cveproduct = topiaCveProduct.split(",")
                    topiaCve = cveproduct[0]
                    product = cveproduct[1]
                    link = cveproduct[2]
                    patchid = cveproduct[3]
                    patchname = cveproduct[4]
                    patchrelease = cveproduct[5]
                    
                    if nessusCve == topiaCve:
                        topiaHit = True
                        strReportTopiaNessus += (endpointName + "," + nessusCve + "," + topiaCve + "," + product + "," + link + "," + patchid + "," + patchname + "," + patchrelease + "\n")
                    
                if topiaHit == False:
                    strReportTopiaNessus += (endpointName + "," + nessusCve + ",N\\A,N\\A,N\\A" + "\n")        

    
    writeReport(dictState['reportNameTopiavsNessus'],strReportTopiaNessus)

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
    
def ReportVunerabilities():
    lastdate = str(dictState['lastEndpointVulnerabilities'])
    vulncount = vuln.getCountEvents(apikey,urldashboard,lastdate)
    print("Vulnerabilities -> " + str(vulncount))
    
    fr0m = 0
    if fr0m < vulncount:
        with tqdm(total=vulncount,desc="Vulnerabilities") as pbar:
            getAllEndpoitsVulnerabilities(fr0m,1000,vulncount,pbar,lastdate)
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
    fr0m = dictState['lastEndpoints']       
    
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
    incidenttype = "MitigatedVulnerability,DetectedVulnerability"
    lastdate = str(dictState['lastIncidentEventVulnerabilities'])
    eventcount = incidents.getIncidentesEventsCountbyType(apikey,urldashboard,incidenttype,lastdate)
    print("Event Incident Vulnerabilities -> " + str(eventcount))
    
    fr0m = 0    
    if fr0m < eventcount:
        with tqdm(total=eventcount,desc="Event Vulnerabilities") as pbar:            
            getAllIncidentEventVulnerabilities(fr0m,100,eventcount,pbar,incidenttype,lastdate)
    else:
        print("Done!")

def ReportEndpointPatchs():
    df = pd.read_csv(dictState['reportAssets'])

    print(df.size)
    

    with tqdm(total=len(df.index),desc="Endpoint Pacths") as pbar:            

        for ind in df.index:
            #pbar.update()
            endpointhash = df['HASH'][ind]
            endpointname = df['HOSTNAME'][ind] 
            countptchs = patchs.getCountEndpointsPatchs(apikey,urldashboard,endpointhash)
            #print(endpointname + "," + str(countptchs))
            strcountendpointpatchs = endpointname + "," + str(countptchs) + "\n"
            writeReport(dictState['reportCountEndpointPatchs'],strcountendpointpatchs)         
            strEndpointPatchs = patchs.getEndpointsPatchs(apikey,urldashboard,0,1000,df['HASH'][ind],df['HOSTNAME'][ind],df['SO'][ind])
            writeReport(dictState['reportNameEndpointPatchs'],strEndpointPatchs)

        pbar.close()

def ReportTopiavsNessus(reportNessusName):
    lstEndpointName = getEnpointsNameDdupNessus(reportNessusName)
    getReportTopiaNessus(lstEndpointName,reportNessusName)   

def ReportGroupsAtrributesTags():
    groupscount = assets.getEndpointGroupsCount(apikey,urldashboard)
    print("Endpoints Groups-> " + str(groupscount))
    fr0m = 0       
    
    if fr0m < groupscount:
        #deltacount = endpointcount - fr0m
        with tqdm(total=groupscount,desc="EndpointGroups") as pbar:            
            getAllEndpoitsGroups(fr0m,300,groupscount,pbar)
    else:
        print("Done!")   


def main():    
    reportstogen = []

    if args.allreports:
        ReportTaskEvents()
        ReportVunerabilities()
        ReportEndpoints()
    
    elif args.assetsreport:
        ReportEndpointsAttributes()
        ReportEndpointScores()
        ReportEndpoints()
        ReportGroupsAtrributesTags()
        
        #reportstogen.append(dictState['reportAssets'])        
        #generateExcel(reportstogen)
    
    elif args.tasksreport:
        ReportTaskEvents()

        reportstogen.append(dictState['reportNameEventsTasks'])        
        generateExcel(reportstogen)

    elif args.vulnreport:
        ReportVunerabilities()

        reportstogen.append(dictState['reportNameVulnerabilities'])        
        generateExcel(reportstogen)

    elif args.patchsreport:
        #ReportProdctsVersions()
        ReportEndpointPatchs()

        #reportstogen.append(dictState['reportNameProducts'])        
        #generateExcel(reportstogen)

    elif args.incidentvulreport:
        ReportIncident()

        #reportstogen.append(dictState['reportNameVulnerabilities'])        
        #generateExcel(reportstogen)

    elif args.topiavsnessus:
        ReportTopiavsNessus(args.nessuscve)

        reportstogen.append(dictState['reportNameTopiavsNessus'])        
        generateExcel(reportstogen)

    else:
        print("Select one report and try again!!!")

if __name__ == '__main__':
    main()




