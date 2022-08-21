
#Author: Joaldir Rani

import sys
import pandas as pd

import VickyAuthentication as auth
import VickyState as state
import EndpointsEventTask as tasks
import EndpointVulnerabilities as vuln
import Endpoint as assets
import PatchsByAssets as patchs

# Get the Credentials
dictCred = auth.getState()
apikey = dictCred['apiKey']
urldashboard = dictCred['dashboard']

#Get the Stats and Reports Names
dictState = state.getState()

def getAllEndpoitsTasks(fr0m,siz3,count):
    
    strTasks = tasks.getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportNameEventsTasks'],strTasks)

    print("fr0m ->" + str(fr0m))
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllEndpoitsTasks(fr0m,siz3,count)
    else:
        print(count)
        print("Tasks Report is Done!")

def getAllEndpoitsVulnerabilities(fr0m,siz3,count):
    
    strVulnerabilities = vuln.getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportNameVulnerabilities'],strVulnerabilities)

    print("fr0m ->" + str(fr0m))
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllEndpoitsVulnerabilities(fr0m,siz3,count)
    else:
        print(count)
        print("Vulnerabilities Report is Done!")

def getAllEndpoits(fr0m,siz3,count):
    strEndpoints = assets.getEndpoints(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportNameEndpoints'],strEndpoints)

    print("fr0m ->" + str(fr0m))
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllEndpoits(fr0m,siz3,count)

    else:
        print("Endpoints Report is Done!")

def getAllEndpointsPatchsHashs():
    strEndpoints = assets.getEndpoints(apikey,urldashboard,810,10)
    for asset in strEndpoints.splitlines():
        endpoint = asset.split(",")
        endpointName = endpoint[1] 
        endpointHash = endpoint[2]

        patchscount = patchs.getCountEndpointsPatchs(apikey,urldashboard,endpointHash)
        print(patchscount)
        getAllPatchsEndpoint(0,100,patchscount,endpointHash,endpointName)


def getAllPatchsEndpoint(fr0m,siz3,count,endpointHash,endpointName):
    strPatchEnpoints = patchs.getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointHash,endpointName)
    writeReport(dictState['reportNameEndpointPatchs'],strPatchEnpoints)

    print("fr0m ->" + str(fr0m))
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllPatchsEndpoint(fr0m,siz3,count,endpointHash,endpointName)

    else:
        print(endpointName + " Patchs is Done!")

def getAllCVEsbyEndpointName(fr0m,siz3,count,endpointName):
    strCVEs = vuln.getCVEsbyEndpointName(apikey,urldashboard,fr0m,siz3,endpointName)
    writeReport(dictState['reportNameEndpointCVEs'],strCVEs)

    print("fr0m ->" + str(fr0m))
    
    fr0m += siz3   
    
    if fr0m < count:
        getAllCVEsbyEndpointName(fr0m,siz3,count,endpointName)

    else:
        print("Endpoints CVEs is Done!")


def writeReport(reportName,strText):
    try:
        with open(reportName, 'a', encoding='UTF8') as report:
            report.write(strText)
        report.close()
    except:
        print("Somthing wrong with file")

#beta genaration report in excel
def generateExcel():
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


def main():
    print("""Change auth.json with API key and Dasboard""")
    print("APIKey is -> " + apikey)
    print("Dashboard -> " + urldashboard)
    print("Change state.json for Report Names")

    # uncomment for generate Assets Report
    #endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    #print(endpointcount)
    #getAllEndpoits(0,500,endpointcount)
    
    # uncomment for generate Tasks
    #taskcount = tasks.getCountEvents(apikey,urldashboard)
    #print(taskcount)
    #getAllEndpoitsTasks(0,500,taskcount)

    # uncomment for generate Vulnerabilities
    #vulncount = vuln.getCountEvents(apikey,urldashboard)
    #print(vulncount)
    #getAllEndpoitsVulnerabilities(0,500,vulncount)

    # todo
    # uncomment for generate all pacths by endpoints hash
    #getAllEndpointsPatchsHashs()

    # todo
    # uncomment for list all CVEs by Hostname
    #endname = "<ENDPOINT_NAME>"
    #count = vuln.getCountCVEs(apikey,urldashboard,endname)
    #getAllCVEsbyEndpointName(0,100,count,endname)
    #print(vuln.getCVEsbyEndpointName(apikey,urldashboard,0,100,endname))
    
    # todo
    # uncomment for generate excel from csv report of tasks.
    # generateExcel()

    sys.exit()

if __name__ == '__main__':
    main()




