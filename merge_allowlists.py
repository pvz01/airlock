# Example of how to move (or copy) the hashes from one allowlist to another
#
# This script requires an API key with the following permissions:
#     application
#     application/export
#     application/add
#     application/remove
# 
# The API key must be provided along with the DNS name of your Airlock Server in a
# configuration file named 'airlock.yaml'. Create this with any text editor of your
# choice and save it in the same directory as this script. Use this template:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# 
# To install dependencies, run this command:
#     pip install requests pyyaml

# Import libraries
import requests
import json
import xml.etree.ElementTree as ET
import yaml

# Read server config
with open('airlock.yaml', 'r') as file:
    config = yaml.safe_load(file)

# Calculate base configuration for interacting with server
base_url = f'https://{config['server_name']}:3129'
headers = {'X-APIKey': config['api_key']}

readme_message = '''
Welcome to PVZ's Allowlist Merge tool. This script will query the server for a list of allowlists (formerly known as applications) and ask you to select a source and destination. It then gets the list of hashes for files in the source, adds them to the destination, and [optionally] removes them from the source.'''
print(readme_message)

# Get list of allowlists
print('\nQuerying server to get the list of allowlists')
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers)
print(request_url, response)
allowlists = response.json()['response']['applications']
print('Found', len(allowlists), 'allowlists\n')

# Print list of allowlists
for index, item in enumerate(allowlists):
    print(f'{index+1}: {item["name"]} ({item["applicationid"]})')

# Prompt to choose source allowlist
user_input = input('\nWhich allowlist do you want to copy hashes from (source)? ')
index = int(user_input)-1
allowlist_source = allowlists[index]

# Prompt to choose destination allowlist
user_input = input('\nWhich allowlist do you want to copy hashes to (destination)? ')
index = int(user_input)-1
allowlist_destination = allowlists[index]

# Prompt to choose copy versus move allowlist
user_input = input('\nDo you want to remove hashes from the source after writing to the destination (YES | NO)? ')
if user_input.lower() == 'yes':
    enable_move = True
else:
    enable_move = False

# Print preview of operation to be performed
if enable_move:
    print('\nYou chose to MOVE hashes from\n', allowlist_source, '\nto\n', allowlist_destination)
else:
    print('\nYou chose to COPY hashes from\n', allowlist_source, '\nto\n', allowlist_destination)

# Get the source allowlist from the server
print('\nRunning export of the source allowlist')
request_url = base_url + '/v1/application/export'
payload = {'applicationid': allowlist_source['applicationid']}
response = requests.post(request_url, headers=headers, json=payload)
print(request_url, response)
xml_content = response.text

# Parse the exported allowlist to get the list of hashes
print('\nParsing source allowlist to generate list of hashes')
root = ET.fromstring(xml_content)
sha256_hashes = [file.find('sha256').text for file in root.findall('.//fileload')]
print('Found', len(sha256_hashes), 'hashes to be moved')

# Add hashes to the destination allowlsit
print('\nAdding the hashes to', allowlist_destination['name'])
request_url = base_url + '/v1/hash/application/add'
payload = {'applicationid': allowlist_destination['applicationid'],
           'hashes': sha256_hashes}
response = requests.post(request_url, headers=headers, json=payload)
print(request_url, response)

if enable_move:
    # Remove hashes from the source allowlist
    print('\nRemoving the hashes from', allowlist_source['name'])
    request_url = base_url + '/v1/hash/application/remove'
    payload = {'applicationid': allowlist_source['applicationid'],
            'hashes': sha256_hashes}
    response = requests.post(request_url, headers=headers, json=payload)
    print(request_url, response)

print('\nDone.')