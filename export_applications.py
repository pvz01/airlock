# Example showing how to bulk export your Application Captures to disk
# 
# Use this command to install prerequisites:
#     pip install requests

#required third-party libraries
import requests
import json

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#if configuration was not provided in-line above, prompt for it
if base_url == 'https://fqdn-of-server:3129':
    server_name = input('Name or IP address of Airlock Server: ')
    base_url = 'https://' + server_name + ':3129'
if headers['X-APIKey'] == 'api-key-here':
    api_key = input('API Key: ')
    headers['X-APIKey'] = api_key

#get list of appplications
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers)
print(response.status_code, request_url)
applications = response.json()['response']['applications']
print('Found', len(applications), 'applications')

#iterate through the list of applications
for application in applications:
    
    #get the application from the server
    request_url = base_url + '/v1/application/export'
    payload = {'applicationid': application['applicationid']}
    response = requests.post(request_url, headers=headers, json=payload)
    print(response.status_code, request_url)
    xml_content = response.text
    
    #write it to disk
    filename = f'{application["name"]}.xml'
    with open(filename, 'w') as xml_file:
        xml_file.write(xml_content)
        print(application['applicationid'], application['name'], 'written to', filename)