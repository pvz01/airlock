# Description:
# Example of how to perform a bulk move of a list of hostnames


#required third-party libraries (use 'pip install libraryname' to install)
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


#ssl verification mode - change to false for lab servers without proper cert
verify_ssl = True
if not verify_ssl:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#calculate base configuration used for all requests
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}


#read list of hostnames from disk
hostnames = []
with open(filename, 'r') as file:
    for line in file:
        hostname = line.strip()
        hostnames.append(hostname)
if len(hostnames) < 1:
    print('ERROR: Unable to read hostnames from', filename)
    sys.exit(0)
print('INFO: Read', len(hostnames), 'hostnames from', filename)
print(hostnames)


#get list of groups from server 
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
    print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
    sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')


#print the groups and ask user to select one
for index, item in enumerate(groups):
    print(f'{index}: {item["name"]} ({item["groupid"]})')
index = int(input('Which group do you want to move the agents to? '))
group = groups[index]
print('INFO: You chose', group)


#prompt user to proceed
proceed = input('Are you sure you want to move ' + str(len(hostnames)) + ' agents to the group "' + group['name'] + '"? Enter YES to proceed: ')
if proceed.lower() != 'yes':
    sys.exit(0)


#perform the moves
print('Attempting to move', len(hostnames), 'devices')
counter = 1
successful_move_counter = 0
errors = []


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
        errors.append(hostname)
    else:    
        agentid = response['response']['agents'][0]['agentid']
        print('INFO: Found a match. Agent ID is', agentid)
    
        #perform the move
        request_url = f'{base_url}v1/agent/move'
        payload = {'agentid': agentid, 'groupid': group['groupid']}
        print('INFO: Moving agent with GUID', agentid, 'to group with GUID', group['groupid'])
        response = requests.post(request_url, headers=headers, verify=verify_ssl, json=payload)
        if response.status_code == 200:
            print('Success')
            successful_move_counter += 1
        else:
            print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
    counter += 1

print('Successfully moved', successful_move_counter, 'devices.')
if len(errors) > 0: 
    print('Encountered', len(errors), 'total errors. Those errors were for these hostnames:')
    for hostname in errors:
        print(hostname) 
