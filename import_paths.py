# Example of how to bulk import a list of path exclusions from a text file on disk to a single policy
# 
# Use this command to install prerequisites:
#     pip install requests

import requests, json, sys

#prompt for config
server_fqdn = input('Enter server fqdn: ')
server_port = input('Enter server port, or press return to accept the default (3129): ')
if server_port == '':
	server_port = 3129
api_key = input('Enter API key: ')
filename = input('Create a plain text file with one path per line. Enter name of that file here, or press return to accept the default (paths.txt): ')
if filename == '':
	filename = 'paths.txt'

#option to disable SSL certificate verification when running against a non-prod server
is_lab_server = False
if is_lab_server:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
	verify_ssl = True

#read list of paths from disk
paths = []
with open(filename, 'r') as file:
	for line in file:
		path = line.strip().strip('"').strip("'")
		paths.append(path)
if len(paths) < 1:
	print('ERROR: Unable to read paths from', filename)
	sys.exit(0)
print('INFO: Read', len(paths), 'paths from', filename)
for path in paths:
	 print(path)

#calculate base configuration used for requests to server
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}

#get list of groups
request_url = f'{base_url}v1/group'
print('INFO: Getting list of groups from the server')
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

#ask user which group they want to add the paths to
for index, item in enumerate(groups):
	print(f'{index}: {item["name"]} ({item["groupid"]}) (Parent: {item["parent"]})')
group_selection = input('Which group do you want to add the Path Exclusions to? ')
group = groups[int(group_selection)]
print('INFO: You chose', group)
payload = {'groupid': group['groupid']}

#sanity check
proceed = input('Are you sure you want to add ' + str(len(paths)) + ' path exclusions to the group "' + group['name'] + '"? Enter YES to proceed: ')
if proceed.lower() != 'yes':
	sys.exit(0)

#add the paths to the selected group
request_url = f'{base_url}v1/group/path/add'
for path in paths:
	payload['path'] = path
	response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
	if response.status_code != 200:
		print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url, 'with headers', headers, 'and payload', payload)
		sys.exit(0)
	else:
		print('INFO: Successfully added', payload['path'], 'to group', payload['groupid'])
