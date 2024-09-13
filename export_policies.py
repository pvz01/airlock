# export_policies.py
# Version: 1.0
# Last updated: 2024-09-13
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

import requests, json, urllib3, datetime, yaml, re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(config_file_name):
    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', config_file_name, config)
    return config

def sanitize_filename(filename):
    return re.sub(r'[^\w\-_\. ]', '_', filename.replace(' ', '_'))

def get_groups(config):
    print('Getting groups')
    request_url = 'https://' + config['server_name'] + ':3129/v1/group'
    request_headers = {'X-ApiKey': config['api_key']}
    response = requests.post(request_url, headers=request_headers, verify=False)
    print(request_url, response)
    groups = response.json()['response']['groups']
    print('Found', len(groups), 'groups')
    return groups

def get_policy_for_group(group, config):
    print('Getting policy for', group['name'])
    request_url = 'https://' + config['server_name'] + ':3129/v1/group/policies'
    request_headers = {'X-ApiKey': config['api_key']}
    request_body = {'groupid': group['groupid']}
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
    print(request_url, request_body, response)
    policy = response.json()['response']
    return policy

def write_policy_to_file(policy, group_name):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M')
    file_name = f"{sanitize_filename(group_name)}_{timestamp}.json"
    with open(file_name, 'w') as file:
        json.dump(policy, file, indent=4)
    print(f"Policy data written to {file_name}")

def main():

    readme_message = """
Welcome to the PVZ's Airlock Policy Export tool. This tool is an example of how to export your Airlock
Policy Groups to disk in JSON format. This may be useful for comparing two policies, for example by 
opening the exported version of each in Notepad++ and using the compare plugin or using other tooling
of your choice which can run a diff on two text files. It may also be useful for maintaining a historic
record of policies if you take exports before and after major changes or at a scheduled interval.

This script makes no changes to your policies. It is a data extract tool only.

This script reads server configuration from a YAML configuration file. Use any text editor to create a 
configuration file with the syntax below, and place it in the same folder as this Python script.

server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey

The API key provided in the YAML must have permission to the following API endpoints:
	group
	group/policies

This script is published under the GNU General Public License v3.0 and is intended as a working example 
of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

	"""
    print(readme_message)

    config_file_name = input('Enter the name of a YAML file containing server configuration, or press return to accept default (airlock.yaml): ')
    if config_file_name == '':
        config = read_config('airlock.yaml')
    else:
        config = read_config(config_file_name)

    groups = get_groups(config)

    for group in groups:
        policy = get_policy_for_group(group, config)
        write_policy_to_file(policy, group['name'])

if __name__ == '__main__':
	main()