# Example showing how to bulk export your Baselines to disk
# 
# Use this command to install prerequisites:
#     pip install requests

#required third-party libraries
import requests
import json

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#get list of baselines
request_url = base_url + '/v1/baseline'
response = requests.post(request_url, headers=headers, verify=False)
print(response.status_code, request_url)
baselines = response.json()['response']['baselines']
print('Found', len(baselines), 'baselines')

#iterate through the list of baselines
for baseline in baselines:
    
    #get the baseline from the server
    request_url = base_url + '/v1/baseline/export'
    payload = {'baselineid': baseline['baselineid']}
    response = requests.post(request_url, headers=headers, json=payload, verify=False)
    print(response.status_code, request_url)
    xml_content = response.text
    
    #write it to disk
    filename = f'{baseline["name"]}.xml'
    with open(filename, 'w') as xml_file:
        xml_file.write(xml_content)
        print(baseline['baselineid'], baseline['name'], 'written to', filename)