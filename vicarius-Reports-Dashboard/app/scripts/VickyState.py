import json

def getState():
    try:
        with open('/usr/src/app/reports/state.json') as f:
            data = f.read()  
        
        dictState = json.loads(data)    
        return dictState

    except:
        print("state.json file is not found!")


def setState(dictState):

    with open('/usr/src/app/reports/state.json', 'w') as convert_file:
        convert_file.write(json.dumps(dictState, indent=2))
    
    #print(dictState)