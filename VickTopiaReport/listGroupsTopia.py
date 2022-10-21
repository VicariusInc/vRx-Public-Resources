import requests
import json

def searchEndpointsGroupTags(tags):
    print(tags)


headers = {
    'Accept': 'application/json',
    'Vicarius-Token': 'HZZRrL9tdRnNjTVaF3myGHDYSKUYrQNP9xFldaJRJL7BD25GAR7mZlaIrS8N0tbLNQYIqrTHbOumclUq0PPdZVUEEttUo4R5H3PHzLy1PfBc87MqTMeSzmM6B45LzqIFoVj2uVAKbbEfdwjyQTAD1rIiPp2BvGZJstJvJnP5e204k64BUjtNwhI8KMeaOqJ0YSFBHDAolM5xwieOldEr2ixC8Fmf4QMnZ22GmpRVtp1x4G3rnBqPG52pbd9TkOy4',
}

params = {
    'from': '0',
    'size': '100',
    'q': '',
    'sort': '-organizationEndpointGroupUpdatedAt',
}

response = requests.get('https://ish.vicarius.cloud/vicarius-external-data-api/organizationEndpointGroup/search', params=params, headers=headers)
#print(response.text)
jresponse = json.loads(response.text)
#print(json.dumps(jresponse['serverResponseCount'],indent=2))
for i in jresponse['serverResponseObject']:
    #print(i)
    #print(i['organizationEndpointGroupId'])
    print(i['organizationEndpointGroupName'])
    #print(i['organizationEndpointGroupSearchQueries'])
    
    
    if '=in=' in i['organizationEndpointGroupFilters']:
        #print('tese')
        #print(i['organizationEndpointGroupFilters'])
        teste = json.loads(i['organizationEndpointGroupFilters'])
        #print(json.dumps(teste,indent=2))
        listAttributes = []
        for j in teste:
            #print(j['fieldValues']['attributes'])
            prepAttrib = str(j['fieldValues']['attributes']).replace("=in=",":")
            prepAttrib = prepAttrib.replace("(","").replace(")","")
            listAttributes += prepAttrib.split(",")
            searchEndpointsGroupTags(listAttributes)
                


        
