# Example showing how to clean up unwanted data in existing app captures,
# using the example of "remove everything with a Python extension".

#required libraries
import requests
import json
import xml.etree.ElementTree as ET
import hashlib
import sys

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#set the list of file extensions for files that you want to remove
extensions_to_remove = ['.py', '.pyi', '.pyc', '.pyd', '.pyo', '.pyw', '.pyz']

#set True/False whether to prompt user before making changes
safety_check = True

#get list of appplications
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers, verify=False)
print(response.status_code, request_url)
applications = response.json()['response']['applications']
print('Found', len(applications), 'applications')

#iterate through the applications
for application in applications:

    print('\nProcessing application', application['name'])
    
    #get the application
    request_url = base_url + '/v1/application/export'
    payload = {'applicationid': application['applicationid']}
    response = requests.post(request_url, headers=headers, json=payload, verify=False)
    print(response.status_code, request_url)
    xml_content = response.text    

    #parse the XML content, generating lists of unique sha256 values
    sha256_keep = []
    sha256_remove = []

    root = ET.fromstring(xml_content)
    results_section = root.find(".//ResultsSection")

    if results_section is not None:
        for result in results_section.findall('fileload'):
            path_element = result.find('path')
            if path_element is not None:
                path = path_element.text
                sha256_element = result.find('sha256')
                if sha256_element is not None:
                    sha256_value = sha256_element.text
                    if any(path.endswith(extension) for extension in extensions_to_remove):
                        if sha256_value not in sha256_remove:
                            sha256_remove.append(sha256_value)
                    else:
                        if sha256_value not in sha256_keep:
                            sha256_keep.append(sha256_value)

    print('Identified', len(sha256_remove), 'files to be removed from', application['name'], 'based on having one of these extensions:', extensions_to_remove)
    print('This application also contains', len(sha256_keep), 'other files, which will not be removed.')
    
    if len(sha256_remove) > 0:
        
        if safety_check:
            user_response = input('Do you want to remove the matching files? Enter YES or NO: ')
            if user_response.lower() != 'yes':
                print('Skipping additional processing of application', application['name'], 'based on your reponse', user_response)
                continue
                
        print('Removing', len(sha256_remove), 'hashes from', application['name'])
        
        request_url = base_url + '/v1/hash/application/remove'
        payload = {'applicationid': application['applicationid'],
                   'hashes': sha256_remove}
        response = requests.post(request_url, headers=headers, json=payload, verify=False)
        print(response.status_code, request_url, payload)
    
    print('\nDone processing application', application['name'])
