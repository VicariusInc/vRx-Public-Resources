#Author Joaldir

from datetime import datetime
import requests
import json
import datetime
import sys

apikey = ''
urldashboard = ''

f = open('VickyReportApiTasksEvents_v1.0.csv', 'a', encoding='UTF8')

f.write('Asset,TaskType,PublisherName,PathOrProduct,PathOrProductDesc,ActionStatus,MessageStatus,Username,CreateAt,UpdateAt\n')

def getCountTasksEvents(apikey,urldashboard):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/count', headers=headers)

    jsonresponse = json.loads(response.text)
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def timestamptodatetime(timestamp_with_ms):

    timestamp, ms = divmod(timestamp_with_ms, 1000)
    dt = datetime.datetime.fromtimestamp(timestamp) + datetime.timedelta(milliseconds=ms)    
    formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
  
    return formatted_time

def getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,count):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)


    for i in parsed['serverResponseObject']:
        #print(i)
        asset = i['taskEndpointsEventEndpoint']['endpointName']
        
        try:
            username = i['taskEndpointsEventTask']['taskUser']['userFirstName']
            username = username + " " + i['taskEndpointsEventTask']['taskUser']['userLastName']
        except:
            username=""
        
        try:
            taskType = i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']
        except:
            taskType = ""

        try:
            publisherName = i['taskEndpointsEventTask']['taskPublisher']['publisherName']
        except:
            publisherName = ""

        pathproduct = ""
        pathproductdesc = ""

        if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:            
            pathproduct = i['taskEndpointsEventTask']['taskPatch']['patchName']
            try:
                pathproductdesc = i['taskEndpointsEventTask']['taskPatch']['patchDescription']
            except:
                pathproductdesc = ""
        
        if 'productName' in i['taskEndpointsEventTask']['taskProduct']:
            pathproduct = i['taskEndpointsEventTask']['taskProduct']['productName']
        
        if 'ActivateTopia' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
            actionStatus = taskType
            messageStatus = ""
            
        else:
            try:
                actionStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesActionStatus']['actionStatusName']
                messageStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesStatusMessage']
            except:
                actionStatus = ""
                messageStatus = ""
        
        createAt = timestamptodatetime(i['analyticsEventCreatedAt'])
        updateAt = timestamptodatetime(i['analyticsEventUpdatedAt'])

        pathproductdesc = pathproductdesc.replace("\r","").replace("\n",">>")
        pathproductdesc = pathproductdesc.replace('"',"").strip('\n')

        messageStatus = messageStatus.replace("\r","").replace("\n",">>")
        messageStatus = messageStatus.replace('"',"").strip('\n')
        
        f.write(asset + "," + taskType + "," + publisherName + "," + pathproduct + ",\"" + pathproductdesc + "\"," + actionStatus + ",\"" + messageStatus + "\"," + username + "," + createAt + "," + updateAt + "\n")
        
    fr0m = fr0m + siz3

    if fr0m < count:
        getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,count)
    else:
        f.close()
        sys.exit()
    
fr0m = 0
siz3 = 50
count = getCountTasksEvents(apikey,urldashboard)
print(count)
getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,count)