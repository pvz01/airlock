# Example of how to move all approved publishers between groups, for example if they were
# originally approved at the child level and you want to move them to the parent so that
# they are inherited by all of the children. Prompts you for configuration. Only moves
# publishers which exist in the source but not in the destination. 

import requests
import json
import sys

#enable/disable verbost printing of every request url, payload, and response code
debugmode = False  #set to either True or False

#prompt for config
server_fqdn = input('Server: ')
base_url = f'https://{server_fqdn}:3129'
api_key = input('API key: ')
headers = {'X-APIKey': api_key}

#get list of groups
request_url = f'{base_url}/v1/group'
response = requests.post(request_url, headers=headers, verify=False)
if debugmode:
    print(response.status_code, request_url)
groups = response.json()['response']['groups']

#ask user which group they want to copy publishers from
for index, item in enumerate(groups):
    print(f'{index}: {item["name"]} ({item["groupid"]})')
user_input = input('Which group do you want to move publishers from? ')
source_group = groups[int(user_input)]

#ask user which group they want to copy publishers to
for index, item in enumerate(groups):
    print(f'{index}: {item["name"]} ({item["groupid"]})')
user_input = input('Which group do you want to move publishers to? ')
destination_group = groups[int(user_input)]

#sanity check that user didn't enter group for both prompts
if source_group['groupid'] == destination_group['groupid']:
    print('ERROR: You chose the same group for both source and destination')
    sys.exit(0)

#get publishers list for source policy
request_url = f'{base_url}/v1/group/policies'
payload = {'groupid': source_group['groupid']}
response = requests.post(request_url, headers=headers, json=payload, verify=False)
if debugmode:
    print(response.status_code, request_url, payload)
publishers = response.json()['response']['publishers']
if publishers is None:
    source_publishers = []
else:
    source_publishers = [entry['name'] for entry in publishers]
print('Source group', source_group['name'], 'has', len(source_publishers), 'publishers:', source_publishers)

#get publishers list for destination policy
request_url = f'{base_url}/v1/group/policies'
payload = {'groupid': destination_group['groupid']}
response = requests.post(request_url, headers=headers, json=payload, verify=False)
if debugmode:
    print(response.status_code, request_url, payload)
publishers = response.json()['response']['publishers']
if publishers is None:
    destination_publishers = []
else:
    destination_publishers = [entry['name'] for entry in publishers]
print('Destination group', destination_group['name'], 'has', len(destination_publishers), 'publishers:', destination_publishers)

#calculate which publishers need to be moved
publishers_to_move = []
for publisher in source_publishers:
    if publisher not in destination_publishers:
        publishers_to_move.append(publisher)
if len(publishers_to_move) > 0:
    print('Identified', len(publishers_to_move), 'to be moved:', publishers_to_move)
else:
    print('No publishers identified to be moved')
    sys.exit(0)
        
#move the publishers
for publisher in publishers_to_move:
    
    #add to destination
    request_url = f'{base_url}/v1/group/publisher/add'
    payload = {'groupid': destination_group['groupid'],
               'publisher': publisher}
    print('Adding', publisher, 'to destination group', destination_group['name'])
    response = requests.post(request_url, headers=headers, json=payload, verify=False)
    if debugmode:
        print(response.status_code, request_url, payload)
    
    #remove from source
    request_url = f'{base_url}/v1/group/publisher/remove'
    payload = {'groupid': source_group['groupid'],
               'publisher': publisher}
    print('Removing', publisher, 'from source group', source_group['name'])
    response = requests.post(request_url, headers=headers, json=payload, verify=False)
    if debugmode:
        print(response.status_code, request_url, payload)

    
#re-query for new publisher lists and print summary to console to show results

#get publishers list for source policy
request_url = f'{base_url}/v1/group/policies'
payload = {'groupid': source_group['groupid']}
response = requests.post(request_url, headers=headers, json=payload, verify=False)
if debugmode:
    print(response.status_code, request_url, payload)
publishers = response.json()['response']['publishers']
if publishers is None:
    source_publishers = []
else:
    source_publishers = [entry['name'] for entry in publishers]
print('Source group', source_group['name'], 'has', len(source_publishers), 'publishers:', source_publishers)

#get publishers list for destination policy
request_url = f'{base_url}/v1/group/policies'
payload = {'groupid': destination_group['groupid']}
response = requests.post(request_url, headers=headers, json=payload, verify=False)
if debugmode:
    print(response.status_code, request_url, payload)
publishers = response.json()['response']['publishers']
if publishers is None:
    destination_publishers = []
else:
    destination_publishers = [entry['name'] for entry in publishers]
print('Destination group', destination_group['name'], 'has', len(destination_publishers), 'publishers:', destination_publishers)
