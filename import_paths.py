# Example of how to bulk import a list of path exclusions from a text file on disk to a single policy
# 
# Use this command to install prerequisites:
#     pip install requests

# Import required libraries
import requests
import json
import sys
import yaml

# Suppress ssl warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read airlock server config from a YAML file
config_file_name = 'airlock.yaml'
with open(config_file_name, 'r') as file:
	config = yaml.safe_load(file)
print('Read config from', config_file_name, 'for', config['server_name'])

# Prompt for configuration
filename = input('Create a plain text file with one path per line. Enter name of that file here, or press return to accept the default (paths.txt): ')
if filename == '':
	filename = 'paths.txt'

# Calculate base configuration used for requests to server
base_url = 'https://' + config['server_name'] + ':3129/'
headers = {'X-APIKey': config['api_key']}

# Read paths from input file on disk
paths = []
with open(filename, 'r') as file:
	for line in file:
		path = line.strip().strip('"').strip("'")
		if len(path) > 0: #skips blank lines
			paths.append(path)
if not paths: #list is empty
	print('ERROR: Unable to read paths from', filename)
	sys.exit(0)
print('INFO: Read', len(paths), 'paths from', filename)
for path in paths:
	 print(path)

# Get list of groups
request_url = base_url + 'v1/group'
print('INFO: Getting list of groups from the server')
response = requests.post(request_url, headers=headers, verify=False)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

# Ask user which group they want to add the paths to
for index, item in enumerate(groups):
	print(f'{index+1}: {item["name"]} ({item["groupid"]}) (Parent: {item["parent"]})')
group_selection = input('Which group do you want to add the Path Exclusions to? ')
group = groups[int(group_selection)-1]
print('INFO: You chose', group)
payload = {'groupid': group['groupid']}

#sanity check
proceed = input('Are you sure you want to add ' + str(len(paths)) + ' path exclusions to the group "' + group['name'] + '"? Enter YES to proceed: ')
if proceed.lower() != 'yes':
	sys.exit(0)

#add the paths to the selected group
request_url = base_url + 'v1/group/path/add'
errors = []
successes = []
for path in paths:
	payload['path'] = path
	response = requests.post(request_url, headers=headers, json=payload, verify=False)
	if response.status_code == 200:
		print('INFO: Successfully added', path, 'to group', payload['groupid'])
		successes.append(path)
	else:
		print('ERROR: Unexpected return code', response.status_code, 'on POST', request_url, 'with headers', headers, 'and payload', payload)
		errors.append(path)
print('\nDone.', len(successes), 'paths were successfully imported:\n', json.dumps(successes, indent=4), '\nand', len(errors), 'errors occured:\n', json.dumps(errors, indent=4))
