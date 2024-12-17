# Example of how to remove stale agents based on a text file on disk
# containing a list of agentid values. To generate this list, consider
# running export_agents.py, identifying the agents you want to remove
# through analysis in Excel or similar, and then pasting the list of
# agentid values into a text editor such as Notepad++ or BBEdit.
# 
# Use this command to install prerequisites:
#     pip install requests yaml

import requests
import json
import sys
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

#get airlock server config
with open('airlock.yaml', 'r') as file:
    config = yaml.safe_load(file)

#prompt for configuration
print('\nCreate a plain text file with a list of agendids to remove. One agentid per line, no headers, no leading or trailing spaces, no quotes. For example:\n\naaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nbbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\ncccccccc-cccc-cccc-cccc-cccccccccccc\n\nSave this file in the working directory that you invoked this script from.\n')
filename = input('Enter filename to read agentids from, or enter no value to use the default (agentids.txt): ')
if filename == '':
    filename = 'agentids.txt'

#read list of agentids from disk
agentids = []
try:
    with open(filename, 'r') as file:
        for line in file:
            agentid = line.strip().strip('"').strip("'")
            agentids.append(agentid)
    if len(agentids) < 1:
        print('ERROR: Unable to read agentids from', filename)
        sys.exit(0)
except FileNotFoundError as e:
    print('ERROR: Unable to read agentids from', filename)
    sys.exit(0)      
print('INFO: Read', len(agentids), 'agentids from', filename)
for agentid in agentids:
    print(agentid)

#calculate base configuration used for requests to server
base_url = 'https://' + config['server_name'] + ':3129/'
headers = {'X-APIKey': config['api_key']}

#sanity check
proceed = input('\nAre you sure you want to remove ' + str(len(agentids)) + ' agents? Enter YES to proceed: ')
if proceed.lower() != 'yes':
    sys.exit(0)
    
#perform the removals
print('\nAttempting to remove', len(agentids), 'agents')

counter = 1
successes = []
failures = []

for agentid in agentids:
    print(counter, '/', len(agentids), ':', agentid)
    payload = {'agentid': agentid}
    request_url = f'{base_url}v1/agent/remove'
    response = requests.post(request_url, headers=headers, json=payload, verify=False)
    if response.status_code != 200:
        print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
        failures.append(agentid)
    else:
        print('Success')
        successes.append(agentid)
    counter += 1

#print results
print('\nSuccessfully removed', len(successes), 'agents')
for agentid in successes:
    print(agentid)
print('\nEncountered', len(failures), 'failures')
for agentid in failures:
    print(agentid)
