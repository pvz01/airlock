# add_os_publishers.py
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to add the list of OS publishers required to prevent Enforcement Agents
# from falling into Safe Mode to all parent Policy Groups. A unique benefit of doing this
# programatically as compared to the GUI is that it removes the requirement for File
# Repository entry(s) for each publisher name to exist on your server, meaning you do
# not need to import baselines or otherwise take steps to trigger file repository entry
# creation.
#
# This script requires an API key with the following permissions:
#     group
#     group/policies
#     group/publisher/add
#
# The API key must be provided along with the DNS name of your Airlock Server in a
# configuration file named 'airlock.yaml'. Create this with any text editor of your
# choice and save it in the same directory as this script. Use this template:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# To install dependencies, run this command:
#     pip install requests urllib3 pyyaml

# Import required libraries
import requests, json, urllib3, yaml, os, sys

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Method that reads configuration from a YAML file on disk
def read_config(config_file_name='airlock.yaml'):
    if not os.path.exists(config_file_name):
        print('ERROR: The configuration file', config_file_name, 'does not exist.')
        sys.exit(1)
    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', config_file_name, 'for server', config['server_name'])
    return config

# Method that gets the list of Policy Groups from the server
def get_groups(server_name, api_key):
    request_url = 'https://' + server_name + ':3129/v1/group'
    request_headers = {'X-APIKey': api_key}
    response = requests.post(request_url, headers=request_headers, verify=False)
    #print(request_url, response)
    groups = response.json()['response']['groups']
    print(len(groups), 'policy groups downloaded from server')
    return groups

# Method to retrieve the list of Parent Policy Groups from server
def get_parent_groups(server_name, api_key):
    groups = get_groups(server_name, api_key)
    parent_groups = []
    for group in groups:
        if group['parent'] == 'global-policy-settings':
            parent_groups.append(group)
    print(len(parent_groups), 'parent policy groups found')
    return parent_groups

# Method that gets the list of trusted publishers for a policy group
def get_trusted_publishers(group, server_name, api_key):
    publisher_names = []
    request_url = 'https://' + server_name + ':3129/v1/group/policies?groupid=' + group['groupid']
    request_headers = {'X-APIKey': api_key}
    response = requests.post(request_url, headers=request_headers, verify=False)
    #print(request_url, response)
    publishers = response.json()['response']['publishers']
    if publishers is not None:
        for publisher in publishers:
            publisher_names.append(publisher['name'])    
    print(len(publisher_names), 'trusted publishers downloaded for group', group['name'])
    return publisher_names
    
# Method that adds trusted publishers to policy for a policy group
def add_publishers(publisher_list, group, server_name, api_key):
    print('Adding', len(publisher_list), 'publishers to policy group', group['name'])
    request_url = 'https://' + server_name + ':3129/v1/group/publisher/add'
    request_headers = {'X-APIKey': api_key}
    request_body = {'groupid': group['groupid'],
                    'publisher': publisher_list}
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
    #print(request_url, request_body, response)

# Get Airlock Server config
config = read_config()

# Download list of parent policy groups on the server
groups = get_parent_groups(config['server_name'], config['api_key'])

# Read list of existing trusted publishers for each parent policy group
for group in groups:
    group['trusted_publishers'] = get_trusted_publishers(group, config['server_name'], config['api_key'])

# Define a list of publishers required to stay out of [Airlock] Safe Mode
required_publishers = ['Microsoft Corporation', 
                       'Microsoft Windows', 
                       'Microsoft Windows Publisher', 
                       'Software Signing (Mac)', 
                       'CentOS (Linux)', 
                       'Red Hat, Inc. (Linux)', 
                       'Rocky (Linux)', 
                       'Rocky Enterprise Software Foundation (Linux)']

# Iterate throught the list of parent policy groups, adding any required publishers that are missing to each
for group in groups:
    missing_publishers = []
    for publisher in required_publishers:
        if publisher not in group['trusted_publishers']:
            missing_publishers.append(publisher)
    if missing_publishers == []:
        print('Policy group', group['name'], 'already includes the', len(required_publishers), 'required publishers')
    else:
        add_publishers(missing_publishers, group, config['server_name'], config['api_key'])

print('Done!')
