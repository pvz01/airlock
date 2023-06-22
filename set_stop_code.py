# Example of how to set agent stop code on multiple policies
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
new_stop_code = input('Enter new Agent Stop Code: ')

#option to disable SSL certificate verification when running against a non-production server
is_lab_server = True
if is_lab_server:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
	verify_ssl = True

#calculate base configuration used for requests to server
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}

#get list of groups and print results to console
request_url = f'{base_url}v1/group'
print('\nINFO: Getting list of groups from the server')
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')
for index, item in enumerate(groups):
	print(f'{index}: {item["name"]} ({item["groupid"]}) (Parent: {item["parent"]})')

#define lists to track results
successes = []
failures = []
skipped = []

#iterate through the groups and ask user if they want to modify stop code for each
for group in groups:
	if 'yes' == input('\nDo you want to enable Agent Stop code on ' + group["name"] + ' ' + group["groupid"] + ' and set it to ' + new_stop_code + ' (YES | NO)? ').lower():
		print('INFO: Attempting to set Agent Stop Code on group', group['groupid'])
		request_url = f'{base_url}v1/group/settings/agentstopcode'
		payload = {'groupid': group['groupid'],
		 			'agentstopcode': new_stop_code}
		response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
		if response.status_code != 200:
			print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url, 'with headers', headers, 'and payload', payload)
			failures.append(group)
		else:
			print('INFO: Success')
			successes.append(group)
	else:
		print('INFO: Skipping group based on your response above')
		skipped.append(group)

#print results to console
print('\nSuccessfully modified the agent stop code on', len(successes), 'groups')
for group in successes:
	print(group['name'], group['groupid'])

print('\nSkipped', len(skipped), 'groups')
for group in skipped:
	print(group['name'], group['groupid'])

print('\nFailed to modify agent stop code on', len(failures), 'groups')
for group in failures:
	print(group['name'], group['groupid'])