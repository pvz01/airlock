# Example of how to move a list of hostnames from a text file on disk to a new group
# 
# Use this command to install prerequisites:
#     pip install requests

#required libraries for interacting with REST API
import requests
import json
import sys

#prompt for configuration
server_fqdn = input('Server fqdn: ')
api_key = input('API key: ')
filename = input('Name of TXT file with list of hostnames to move: ')
if filename == '':
	filename = 'hostnames.txt'

#read list of hostnames from disk
hostnames = []
with open(filename, 'r') as file:
	for line in file:
		hostname = line.strip().strip('"').strip("'")
		hostnames.append(hostname)
if len(hostnames) < 1:
	print('ERROR: Unable to read hostnames from', filename)
	sys.exit(0)
print('INFO: Read', len(hostnames), 'hostnames from', filename)
print(hostnames)

#calculate base configuration used for requests to server
base_url = 'https://' + server_fqdn + ':3129/'
headers = {'X-APIKey': api_key}

#read group list
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=False)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

#prompt for group selection
for index, item in enumerate(groups):
    print(f'{index+1}: {item["name"]} ({item["groupid"]})')
user_input = input('Which group do you want to move the agents to? ')
index = int(user_input)-1
group = groups[index]
print('INFO: You chose', group)

#prompt for sanity check
proceed = input('Are you sure you want to move ' + str(len(hostnames)) + ' agents to the group "' + group['name'] + '"? Enter YES to proceed: ')
if proceed.lower() != 'yes':
	sys.exit(0)

#perform the moves
print('Attempting to move', len(hostnames), 'devices to the group', group['name'])

counter = 1
successes = []
failures = []

for hostname in hostnames:
	print(counter, '/', len(hostnames))

	#find agent id(s)
	print('INFO: Searching for agent id for hostname', hostname)
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
			payload = {'agentid': agentid, 'groupid': group['groupid']}
			print('INFO: Moving agent', hostname , 'with GUID', agentid, 'to group', group['name'], 'with GUID', group['groupid'])
			response = requests.post(request_url, headers=headers, json=payload, verify=False)
			if response.status_code == 200:
				print('Success')
				successes.append(hostname)
			else:
				print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
				failures.append(hostname)
	counter += 1

#print results
print('\nSuccessfully moved', len(successes), 'devices to', group['name'], group['groupid'])
for hostname in successes:
	print(hostname)
print('\nEncountered', len(failures), 'failures')
for hostname in failures:
	print(hostname)
