# Example of how to create clone an existing group and apply the same policies to it

#set server configuration
base_url = 'https://SERVER-NAME:3129/'
headers = {'X-APIKey': 'API-KEY'}

#required libraries for interacting with REST API
import requests
import json

#read group list
request_url = f'{base_url}/v1/group'
response = requests.post(request_url, headers=headers, verify=False)
groups = response.json()['response']['groups']

#prompt for group selection
for index, item in enumerate(groups):
    print(f'{index+1}: {item["name"]} ({item["groupid"]})')
user_input = input('Which group do you want to make a copy of? ')
index = int(user_input)-1
source_group = groups[index]
print('\nSource group to copy policies from:', source_group)

#create new group with _copy suffix in same parent as original group
new_group_name = f"{source_group['name']}_copy"
new_group_parent = source_group['parent']
print('\nCreating new group', new_group_name)
request_url = f'{base_url}/v1/group/new'
payload = {'name': new_group_name,
           'parent': new_group_parent,
           'hidden': '0'}
response = requests.post(request_url, headers=headers, json=payload, verify=False)

#read updated group list to validate creation of new group and get it's groupid
request_url = f'{base_url}/v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
groups_with_new_group = response.json()['response']['groups']
for group in groups_with_new_group:
    if group['name'] == new_group_name:
        if group['parent'] == new_group_parent:
            target_group = group
print('\nTarget group to copy policies to:', target_group)

#assign the policies applied to source group to the new group
request_url = f'{base_url}/v1/group/assign'
print('\nApplying the policies applied to', source_group['name'], 'to', target_group['name'])
payload = {'groupid': source_group['groupid'],
           'targetgroupid': target_group['groupid']}
response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
