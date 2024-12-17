#CONFIGURATION
airlock_server_fqdn = 'foo'
airlock_api_key = 'bar'

#RUNTIME

#import the required third-party libraries
import requests
import json
import xml.etree.ElementTree as ET
import yaml

#suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#read server config
with open('airlock.yaml', 'r') as file:
    config = yaml.safe_load(file)

#calculate base configuration for interacting with server
base_url = f'https://{config['server_name']}:3129'
headers = {'X-APIKey': config['api_key']}

print('Welcome to the Allowlist Merge tool. This script will query the server for a list of allowlists (formerly known as applications) and ask you to select a source and destination. It then gets the list of hashes for files in the source, adds them to the destination, and removes them from the source.')

#get list of allowlists
print('\nQuerying server to get the list of allowlists')
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers, verify=False)
#print(response.status_code, request_url)
allowlists = response.json()['response']['applications']
print('Found', len(allowlists), 'allowlists\n')

#print list of allowlists
for index, item in enumerate(allowlists):
    print(f'{index+1}: {item["name"]} ({item["applicationid"]})')

#prompt to choose source allowlist
user_input = input('\nWhich allowlist do you want to move hashes from (source)? ')
index = int(user_input)-1
allowlist_source = allowlists[index]

#prompt to choose destination allowlist
user_input = input('\nWhich allowlist do you want to move hashes to (destination)? ')
index = int(user_input)-1
allowlist_destination = allowlists[index]

print('\nYou chose to move hashes from\n', allowlist_source, '\nto\n', allowlist_destination)

#get the source allowlist from the server
print('\nRunning export of the source allowlist')
request_url = base_url + '/v1/application/export'
payload = {'applicationid': allowlist_source['applicationid']}
response = requests.post(request_url, headers=headers, json=payload, verify=False)
xml_content = response.text

#parse the exported allowlist to get the list of hashes
print('Parsing source allowlist to generate list of hashes')
root = ET.fromstring(xml_content)
sha256_hashes = [file.find('sha256').text for file in root.findall('.//fileload')]
print('\nFound', len(sha256_hashes), 'hashes to be moved')

#add hashes to the destination allowlsit
print('\nAdding the hashes to', allowlist_destination['name'])
request_url = base_url + '/v1/hash/application/add'
payload = {'applicationid': allowlist_destination['applicationid'],
           'hashes': sha256_hashes}
response = requests.post(request_url, headers=headers, json=payload, verify=False)

#remove hashes from the source allowlist
print('\nRemoving the hashes from', allowlist_source['name'])
request_url = base_url + '/v1/hash/application/remove'
payload = {'applicationid': allowlist_source['applicationid'],
           'hashes': sha256_hashes}
response = requests.post(request_url, headers=headers, json=payload, verify=False)

print('\nDone.')