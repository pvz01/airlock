# Example of how to move a list of hostnames to a new group using in-line configuration
# Useful for recurring maintenance tasks, for example moving a list of devices between 
# Audit Mode and Enforcement Mode for scheduled maintenance.
# 
# Use this command to install prerequisites:
#     pip install requests
#
# To use the script, create an API key with permission to the following API endpoints
#     group
#     agent/find
#     agent/move
#
# Provide the key along with the server name, the list of hostnames, and the name of 
# the group to move them to on the appropriate lines below.


#CONFIGURATION
airlock_server = 'foo'
airlock_api_key = 'bar'
hostnames = ['hostname01', 'hostname02', 'hostname03']
group_name = 'Your Audit Mode Group'


#RUNTIME

#import required libraries and suppress SSL warnings
import requests
import json
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

#calculate base configuration used for requests to server
base_url = 'https://' + airlock_server + ':3129/'
headers = {'X-APIKey': airlock_api_key}

#query server for list of groups
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=False)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Successfully queried', airlock_server, 'and found list of', len(groups), 'groups')

#find the destination group
destination_group = None
for group in groups:
	if group['name'].lower() == group_name.lower():
		destination_group = group
if destination_group is None:
	print('ERROR: There is not a group with name', f"'{group_name}'", 'to move the devices to. Groups that do exist:')
	for group in groups:
		print('\t', group['name'])
	sys.exit(0)
else:
	print('INFO: Successfully identified destination group with name', destination_group['name'], 'and groupid', destination_group['groupid'])

#perform the moves
print('\nAttempting to move', len(hostnames), 'hostnames to', destination_group['name'], '\n')

counter = 1
successes = []
failures = []

for hostname in hostnames:
	print(counter, '/', len(hostnames), hostname)

	#find agent id(s)
	print('INFO: Searching for agentid(s) for hostname', hostname)
	request_url = f'{base_url}v1/agent/find'
	payload = {'hostname': hostname}
	response = requests.post(request_url, headers=headers, json=payload, verify=False)
	if response.status_code != 200:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
		sys.exit(0)
	response = response.json()
	if response['response']['agents'] == None:
		print('ERROR: No match found for hostname', hostname)
		failures.append(hostname)
	else:    
		agents = response['response']['agents']
		if len(agents) > 1:
			print('WARNING: Found', len(agents), 'matches for hostname', hostname, 'and all of them will be moved')
		for agent in agents:
			agentid = agent['agentid']
			print('INFO: Found a match for', hostname, 'with agent id', agentid)
			
			#execute the move
			request_url = f'{base_url}v1/agent/move'
			payload = {'agentid': agentid, 'groupid': destination_group['groupid']}
			print('INFO: Moving agent', agentid, 'to group', destination_group['groupid'])
			response = requests.post(request_url, headers=headers, json=payload, verify=False)
			if response.status_code == 200:
				print('Success\n')
				successes.append(hostname)
			else:
				print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
				failures.append(hostname)
	counter += 1

#print results
print('\nSuccessfully moved', len(successes), 'devices to', destination_group['name'])
for hostname in successes:
	print(hostname)
print('\nEncountered', len(failures), 'failures')
for hostname in failures:
	print(hostname)
