#Author: Joaldir Rani

import requests
import json
import utils

def getCountEvents(apikey,urldashboard):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/count', params=params, headers=headers)
    jsonresponse = json.loads(response.text)
    responsecount = jsonresponse['serverResponseCount']

    return responsecount
    
def getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '+analyticsEventCreatedAt',
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)

    strTasks = ""
    for i in parsed['serverResponseObject']:
        try:
            automationName = i['taskEndpointsEventTask']['taskAutomation']['automationName']
            automationId = i['taskEndpointsEventTask']['taskAutomation']['automationId']
        except:
            automationName = ""
            automationId = ""

        
        taskid = i['taskEndpointsEventTask']['taskId']
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
        
        createAt = utils.timestamptodatetime(i['analyticsEventCreatedAt'])
        updateAt = utils.timestamptodatetime(i['analyticsEventUpdatedAt'])

        pathproductdesc = pathproductdesc.replace("\r","").replace("\n",">>")
        pathproductdesc = pathproductdesc.replace('"',"").strip('\n')

        messageStatus = messageStatus.replace("\r","").replace("\n",">>")
        messageStatus = messageStatus.replace('"',"").strip('\n')
        
        strTasks += (str(taskid) + "," + str(automationId) + "," + automationName + "," + asset + "," + taskType + "," + publisherName + "," + pathproduct + ",\"" + pathproductdesc + "\"," + actionStatus + ",\"" + messageStatus + "\"," + username + "," + str(createAt) + "," + str(updateAt) + "\n")
    
    return strTasks