#Author: Joaldir Rani

import requests
import json
import utils
from datetime import datetime

def getCountEvents(apikey,urldashboard,lastdate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
        'sort' : '-analyticsEventCreatedAt',
        'q':'analyticsEventCreatedAt>' + str(lastdate),
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/count', params=params, headers=headers)
    jsonresponse = json.loads(response.text)
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,maxdate,mindate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        #'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '-analyticsEventCreatedAt',
        'q':'analyticsEventCreatedAt>' + mindate + ';analyticsEventCreatedAt<' + maxdate,
    }
    
    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)
    print(response)
    #strTasks = ""
    tasks_list = []

    print (maxdate, mindate)
    #print (parsed)
    for i in parsed['serverResponseObject']:
        
        #taskEndpointsEventTask taskOperatingSystem operatingSystemName
        #print(i['taskEndpointsEventTask']['taskOperatingSystem']['operatingSystemName'])
        #if i['taskEndpointsEventTask']['taskTaskType']['taskTypeName'] == "RunScript":
        #    print(json.dumps(i, indent=4, sort_keys=True))
        #print(json.dumps(i, indent=4, sort_keys=True))

        try:
            automationName = i['taskEndpointsEventTask']['taskAutomation']['automationName']
            automationId = i['taskEndpointsEventTask']['taskAutomation']['automationId']
        except:
            automationName = ""
            automationId = ""

        
        taskid = i['taskEndpointsEventTask']['taskId']
        asset = i['taskEndpointsEventEndpoint']['endpointName']
        endpointId = i['taskEndpointsEventEndpoint']['endpointId']
        endpointHash = i['taskEndpointsEventEndpoint']['endpointHash']
        
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
        try:
            orgTeamName = i['taskEndpointsEventTask']['taskAutomation']['automationOrganizationTeam']['organizationTeamName']
        except:
            orgTeamName = ""
        try: 
            runSequence = i['taskEndpointsEventTask']['taskAutomationRun']['automationRunSequence']
        except:
            runSequence = ""
        try:
            assetStatus = i['taskEndpointsEventEndpoint']['endpointEndpointStatus']['endpointStatusName']
        except:
            assetStatus = ""

            

        pathproduct = ""
        pathproductdesc = ""

        if 'taskPatch' in i['taskEndpointsEventTask']:
            if i['taskEndpointsEventTask']['taskPatch'] != {}:
                #print(i['taskEndpointsEventTask']['taskPatch'])
                if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:
                    try:            
                        pathproduct = i['taskEndpointsEventTask']['taskPatch']['patchName']
                    except:
                        pathproduct = ""
                    try:
                        pathproductdesc = i['taskEndpointsEventTask']['taskPatch']['patchDescription']
                        substring = ","
                        if substring in pathproductdesc:
                            pathproductdesc = pathproductdesc.replace(",", " ")
                    except:
                        pathproductdesc = ""
            else:
                pathproduct = ""
                pathproductdesc = ""
        else:
            pathproduct = ""
            pathproductdesc = ""

        

        if 'taskProduct' in i['taskEndpointsEventTask']:
            if 'productName' in i['taskEndpointsEventTask']['taskProduct']:
                try:
                    pathproduct = i['taskEndpointsEventTask']['taskProduct']['productName']
                except KeyError:
                    pathproduct = ""
        else:
            pathproduct = ""


        if 'ApplyPublisherOperatingSystemVersionsPatchs' in taskType:
            pathproduct = i['taskEndpointsEventTask']['taskOperatingSystem']['operatingSystemName']
        
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
        
        if 'RunScript' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
            # set actionstatus to taskTaskStatus taskStatusName
            actionStatus = i['taskEndpointsEventTask']['taskTaskStatus']['taskStatusName']
            messageStatus = ""
            
        createAt = i['analyticsEventCreatedAt']
        updateAt = i['analyticsEventUpdatedAt']
        createAtNano = i['analyticsEventCreatedAtNano']
        updateAtNano = i['analyticsEventUpdatedAtNano']

        try:
            hcreateAt = datetime.fromtimestamp(createAt / 1000).isoformat()
            hupdateAt = datetime.fromtimestamp(updateAt / 1000).isoformat()
        except:
            hcreateAt = 0
            hupdateAt = 0

        pathproductdesc = pathproductdesc.replace("\r","").replace("\n",">>")
        pathproductdesc = pathproductdesc.replace('"',"").strip('\n')
        pathproductdesc = pathproductdesc.replace(",", "")


        messageStatus = messageStatus.replace("\r","").replace("\n",">>")
        messageStatus = messageStatus.replace('"',"").strip('\n')
        
        try:
            #replacing string concatenation for list of task_dict
            #strTasks += (str(taskid) + "," + str(automationId) + "," + automationName + "," + asset + "," + taskType + "," + publisherName + "," + pathproduct + ",\"" + pathproductdesc + "\"," + actionStatus + ",\"" + messageStatus + "\"," + username + "," + str(createAt) + "," + str(updateAt) + "\n")
            task_dict = {
            "endpointId" : endpointId,
            "taskid": taskid,
            "automationId": automationId,
            "automationName": automationName,
            "assetHash": endpointHash,
            "asset": asset,
            "taskType": taskType,
            "publisherName": publisherName,
            "pathproduct": pathproduct,
            "pathproductdesc": pathproductdesc,
            "actionStatus": actionStatus,
            "messageStatus": messageStatus,
            "username": username,
            "orgTeam": orgTeamName,
            "runSequence": runSequence,
            "assetStatus": assetStatus,
            "createAtNano": createAtNano,
            "updateAtNano": updateAtNano,
            "hcreateAt": hcreateAt,
            "hupdateAt": hupdateAt,
            "createAt": createAt,
            "updateAt": updateAt
            }
            tasks_list.append(task_dict)

            lastdate = i['analyticsEventCreatedAt']
        except:
            if lastdate is None: 
                lastdate = maxdate
            if task_dict is None: 
                task_dict = {}
        #print (lastdate)

    #return strTasks,lastdate
    return tasks_list,lastdate