# Example of how to move a list of hostnames from a text file on disk to a new group
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
filename = input('Create a plain text file with one hostname per line. Enter name of that file here, or press return to accept the default (hostnames.txt): ')
if filename == '':
	filename = 'hostnames.txt'

#option to disable SSL certificate verification when running against a non-prod server
is_lab_server = False
if is_lab_server:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
	verify_ssl = True

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
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}

#get list of groups
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

#ask user which group to move the device(s) to
for index, item in enumerate(groups):
	print(f'{index}: {item["name"]} ({item["groupid"]})')
index = int(input('Which group do you want to move the agents to? '))
group = groups[index]
print('INFO: You chose', group)

#sanity check
proceed = input('Are you sure you want to move ' + str(len(hostnames)) + ' agents to the group "' + group['name'] + '"? Enter YES to proceed: ')
if proceed.lower() != 'yes':
	sys.exit(0)

print('Attempting to move', len(hostnames), 'devices to the group', group['name'])

#establish counters and lists to track results
counter = 1
successes = []
failures = []

#iterate through the hostnames
for hostname in hostnames:
	print(counter, '/', len(hostnames))

	#find the agent id of the hostname
	print('INFO: Searching for agent id for hostname', hostname)
	request_url = f'{base_url}v1/agent/find'
	payload = {'hostname': hostname}
	response = requests.post(request_url, headers=headers, verify=verify_ssl, json=payload)
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
			#perform the move
			request_url = f'{base_url}v1/agent/move'
			payload = {'agentid': agentid, 'groupid': group['groupid']}
			print('INFO: Moving agent', hostname , 'with GUID', agentid, 'to group', group['name'], 'with GUID', group['groupid'])
			response = requests.post(request_url, headers=headers, verify=verify_ssl, json=payload)
			if response.status_code == 200:
				print('Success')
				successes.append(hostname)
			else:
				print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
				failures.append(hostname)
	counter += 1

#print results to console
print('\nSuccessfully moved', len(successes), 'devices to', group['name'], group['groupid'])
for hostname in successes:
	print(hostname)
print('\nEncountered', len(failures), 'failures')
for hostname in failures:
	print(hostname)
