#Author: Joaldir Rani

import requests
import json
import utils
import time
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

def getUpdatedTaskEndpointsEvents(apikey,urldashboard,fr0m,siz3,maxdate,mindate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        #'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '-analyticsEventUpdatedAtNano',
        'q':'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate,
    }

def getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,maxdate,mindate):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        #'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '-analyticsEventUpdatedAtNano',
        'q':'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate,
    }
    #print(params)    
    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)
    #print(parsed)
    #strTasks = ""
    tasks_list = []
    if response.status_code == 429:
        print("API Rate Limit exceeded ... Waiting and Trying again")
        time.sleep(60)
        getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,maxdate,mindate)
    #print (maxdate, mindate)
    #print (parsed)
    src = len(parsed['serverResponseObject'])
    #print("length of taskEndpointsEvents/filter Response")
    #print(src)
    if src == 0:
        print("Count is zero")
        tasks_list = 0 
        lastdate = 0
    else:
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
            patchName = ""
            patchFileName = ""
            patchPackageFileName = ""
            patchReleaseDate = i['analyticsEventUpdatedAt']

            if 'taskPatch' in i['taskEndpointsEventTask']:
                if i['taskEndpointsEventTask']['taskPatch'] != {}:
                    #print(i['taskEndpointsEventTask']['taskPatch'])
                    if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:
                        try:            
                            patchName  = i['taskEndpointsEventTask']['taskPatch']['patchName']
                        except:
                            patchName  = ""
                        try:
                            patchFileName = i['taskEndpointsEventTask']['taskPatch']['patchFileName']
                        except:
                            patchFileName = ""
                        try:
                            patchReleaseDate = i['taskEndpointsEventTask']['taskPatch']['patchReleaseDate']
                        except:
                            patchReleaseDate = i['analyticsEventUpdatedAt']
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

            #if 'patchPackageFileName' in i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']:
            #    print(i['taskEndpointsEventOrganizationEndpointPatchPatchPackages'])
            #    patchPackageFileName = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesPatchPackage']['patchPackageFileName']
            
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
                #patchReleaseDate = datetime.fromtimestamp(patchReleaseDate / 1000).isoformat()
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
                "patchName": patchName,
                "patchFileName": patchFileName,
                "patchPackageFileName": patchPackageFileName,
                "patchReleaseDate": patchReleaseDate,
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

                lastdate = i['analyticsEventUpdatedAtNano']
            except:
                if lastdate is None: 
                    lastdate = maxdate
                if task_dict is None: 
                    task_dict = {}
            #print (lastdate)

    #return strTasks,lastdate
    return tasks_list,lastdate

def getTasksEndopintsEventsWaiting(apikey,urldashboard,fr0m,siz3,maxdate,mindate,aID):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        #'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '+analyticsEventUpdatedAtNano',
        'q':'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate +';taskEndpointsEventTask.automationId==' + aID,
    }
    #print(params) 
    # 
    print(aID)
    print(params)   
    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)
    print(response.status_code)
    #print(parsed)
    #strTasks = ""
    tasks_list = []
    if response.status_code == 429:
        print("API Rate Limit exceeded ... Waiting and Trying again")
        time.sleep(60)
        return 0
    #print (maxdate, mindate)
    #print (parsed)
    src = len(parsed['serverResponseObject'])
    #print("length of taskEndpointsEvents/filter Response")
    #print(src)
    if src == 0:
        print("Count is zero")
        tasks_list = 0 
        lastdate = 0
    else:
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
            patchName = ""
            patchFileName = ""
            patchPackageFileName = ""
            patchReleaseDate = i['analyticsEventUpdatedAt']

            if 'taskPatch' in i['taskEndpointsEventTask']:
                if i['taskEndpointsEventTask']['taskPatch'] != {}:
                    #print(i['taskEndpointsEventTask']['taskPatch'])
                    if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:
                        try:            
                            patchName  = i['taskEndpointsEventTask']['taskPatch']['patchName']
                        except:
                            patchName  = ""
                        try:
                            patchFileName = i['taskEndpointsEventTask']['taskPatch']['patchFileName']
                        except:
                            patchFileName = ""
                        try:
                            patchReleaseDate = i['taskEndpointsEventTask']['taskPatch']['patchReleaseDate']
                        except:
                            patchReleaseDate = i['analyticsEventUpdatedAt']
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

            #if 'patchPackageFileName' in i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']:
            #    print(i['taskEndpointsEventOrganizationEndpointPatchPatchPackages'])
            #    patchPackageFileName = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesPatchPackage']['patchPackageFileName']
            
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
                #patchReleaseDate = datetime.fromtimestamp(patchReleaseDate / 1000).isoformat()
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
                "patchName": patchName,
                "patchFileName": patchFileName,
                "patchPackageFileName": patchPackageFileName,
                "patchReleaseDate": patchReleaseDate,
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

                lastdate = i['analyticsEventUpdatedAtNano']
            except:
                if lastdate is None: 
                    lastdate = maxdate
                if task_dict is None: 
                    task_dict = {}
            #print (lastdate)

    #return strTasks,lastdate
    return tasks_list,lastdate
