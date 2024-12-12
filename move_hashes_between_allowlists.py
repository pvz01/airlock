# move_hashes_between_allowlists.py
# Version: 1.0
# Last updated: 2024-12-12
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to move the hash-based approvals from one allowlist to another. This can be 
# useful for promoting hash-based approvals from a staging allowlist which is not approved in
# policy to a production allowlist which is approved in policy.
#
# This script requires an API key for a user in a group with the following API role permissions:
#     application
#     application/export
#     hash/application/add
#     hash/application/remove
#
# This script ingests server configuration from a YAML file called airlock.yaml. This is a simple
# 2-line ASCII text file which can be created with any text editor. Follow this syntax:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
'''
#
# This script is published under the GNU General Public License v3.0 and is intended as a practical 
# example of how to interact with the Airlock Digital REST API. It is not a commercial product and is 
# provided 'as-is' with no support. No warranty, express or implied, is provided, and the use of this
# script is at your own risk.

# Import required libraries
import requests, json, urllib3, yaml, sys, os
import xml.etree.ElementTree as ET

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get server config from YAML on disk
file_name = 'airlock.yaml'
with open(file_name, 'r') as file:
    config = yaml.safe_load(file)
    
# Calculate base configuration for interacting with server
base_url = 'https://' + config['server_name'] + ':3129/v1/'
headers = {'X-ApiKey': config['api_key']}

# Read list of allowlists aka applications
#
# NOTE: In versions of Airlock prior to v5.3.0 (released April 2024), 'Allowlists' were called
# 'Application Captures', or 'Applications' for short. The internals of the product contiunue
# to use the old nomenclature, as does the REST API.
#
url = base_url + 'application'
response = requests.post(url, headers=headers, verify=False)
print(url, response)
applications = response.json()['response']['applications']

# Prompt for selection of source and destination
for index, item in enumerate(applications):
    print(f'{index+1}: {item["name"]} ({item["applicationid"]})')
user_input = input('\nWhich allowlist do you want to move hashes from (source)? ')
source = applications[int(user_input)-1]
user_input = input('\nWhich allowlist do you want to move hashes to (destination)? ')
destination = applications[int(user_input)-1]

# Get the source
url = base_url + 'application/export?applicationid=' + source['applicationid']
response = requests.post(url, headers=headers, verify=False)
print(url, response)

# Parse XML, find unique sha256 values
root = ET.fromstring(response.text)
unique_sha256_values = {elem.text for elem in root.findall('.//sha256')}
sha256_list_to_move = list(unique_sha256_values)

# Print preview of move
print('Found', len(sha256_list_to_move), 'hashes to be moved from', source, 'to', destination)

# Add hashes to destination
url = base_url + 'hash/application/add'
body = {'applicationid': destination['applicationid'],
        'hashes': sha256_list_to_move}
response = requests.post(url, headers=headers, json=body, verify=False)
print(url, response, response.text)

# Remove hashes from source
url = base_url + 'hash/application/remove'
body = {'applicationid': source['applicationid'],
        'hashes': sha256_list_to_move}
response = requests.post(url, headers=headers, json=body, verify=False)
print(url, response, response.text)