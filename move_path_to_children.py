# move_path_to_children.py
# Patrick Van Zandt, Principal Customer Success Manager

# This script uses the /group/path/add and /group/path/remove endpoints in the Airlock Digital
# REST API to move a Path Exclusion from a Parent Policy Group to its Child Policy Groups.
#
# The core use case for this script is if you have a Path Exclusion applied at the parent
# level that you want to remove for some but not all of the children. To do so, it prompts
# you for which Parent Policy Group and Path Exclusion to work with, then adds the Path
# Exclusion to each of the Child Policy Groups, and lastly removes it from the Parent
# Policy Group. This procesisng order ensures that there is no gap in coverage because no version
# of any Child Policy Group will lack the Path Exclusion. After the script completes, you can
# then use the GUI to remove the Path Exclusion from the Child Policy Group(s) where it is no
# longer needeed.
#
# This script is published under the GNU General Public License v3.0 and is intended as a working
# example of how to interact with the Airlock API. It is not a commercial product and is provided 
# 'as-is' with no support. No warranty, express or implied, is provided, and the use of this script
# is at your own risk.
#
# This script requires Python 3.x and several common libraries. To install these dependencies, run
#     pip install requests pyyaml
#
# This script reads configuration from a required configuration file named 'airlock.yaml'. Use any text 
# editor to create this file based on the template below, then save in the same folder as this script.
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# The API key must be for a user that is in a Permission Group with the following REST API Role:
#     group
#     group/policies
#     group/path/add
#     group/path/remove
#


## IMPORT REQUIRED LIBRARIES ##
import requests
import json
import yaml
import os
import sys


## IMPLEMENT CLI FLAG TO ALLOW DISABLING OF SSL VERIFICATION FOR LAB ENVIRONMENTS ##
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (NOT for production)')
_args, _unknown = parser.parse_known_args()
VERIFY_SSL = not _args.insecure
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    sys.stderr.write(
            "\n\033[91m"
            "!!! INSECURE MODE ENABLED !!!\n"
            "SSL certificate verification is DISABLED.\n"
            "\n"
            "This means:\n"
            "  • Your connection is not secure.\n"
            "  • An attacker on the network could intercept or modify traffic\n"
            "    and steal your API key and data (man-in-the-middle attack).\n"
            "\n"
            "If you used this flag by mistake:\n"
            "  • STOP using --insecure immediately.\n"
            "  • REGENERATE your API key in the management console to invalidate the old one.\n"
            "\n"
            "Use ONLY in trusted lab/dev environments or when testing with self-signed certificates.\n"
            "Re-run without --insecure for safe operation.\n"
            "\033[0m\n"
    )
    

## DEFINE A SERIES OF METHODS USED AT RUNTIME ##

# Method that reads configuration from a YAML file on disk
def read_config(config_file_name='airlock.yaml'):

    print('Reading configuration from', config_file_name)
    if not os.path.exists(config_file_name):
        print('ERROR: The configuration file does not exist.',
            'Create a new text file using this template:\n\n'
            'server_name: your-airlock-server\napi_key: your-api-key',
            f"\n\nThen save it in the same folder as this script as '{config_file_name}' and try again."
            )
        sys.exit(1)

    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)

    server_name = config.get('server_name', None)
    if server_name is None:
        print('Error reading server_name from', config_file_name)
        sys.exit(1)

    api_key = config.get('api_key', None)
    if api_key is None:
        print('Error reading api_key from', config_file_name)
        sys.exit(1)

    print('\tServer name', f"'{server_name}'")
    print('\tAPI key ending in', f"'{api_key[-4:]}'")

    return server_name, api_key

# Method that gets the list of Policy Groups from the server
def get_groups(server_name, api_key):
    request_url = 'https://' + server_name + ':3129/v1/group'
    request_headers = {'X-ApiKey': api_key}
    response = requests.post(request_url, headers=request_headers, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json()['response']['groups']

# Method to choose from a list of Policy Groups by prompting the user
def choose_group(groups):
    for index, item in enumerate(groups):
        print(f'\t{index+1}: {item["name"]} ({item["groupid"]})')
    user_response = input('Enter group number: ')
    index = int(user_response)-1
    group = groups[index]
    return group

# Method to get list of Policy Groups that are the children of a specified parent
def get_children(groups, parent):
    children = []
    for group in groups:
        if group['parent'] == parent['groupid']:
            children.append(group)
    return children

# Method to filter a list of Policy Groups and find the parents
def get_parents(groups):
    parents = []
    for group in groups:
        if group['parent'] == 'global-policy-settings':
            parents.append(group)
    return parents

# Method to get the list of Path Exclusions from a Policy Group
def get_paths(server_name, api_key, groupid):
    request_url = 'https://' + server_name + ':3129/v1/group/policies?groupid=' + groupid
    request_headers = {'X-ApiKey': api_key}
    response = requests.post(request_url, headers=request_headers, verify=VERIFY_SSL)
    response.raise_for_status()
    data = response.json()['response']['paths']
    paths = []
    for item in data:
        paths.append(item['name'])
    return paths

# Method to choose from a list of Path Exclusions by prompting the user
def choose_path(paths):
    for index, item in enumerate(paths):
        print(f'\t{index+1}: {item}')
    user_response = input('Enter path number: ')
    index = int(user_response)-1
    path = paths[index]
    return path

# Method to add a Path Exclusion to a Policy Group
def add_path(server_name, api_key, groupid, path):
    path = path.replace('\\\\', '\\')  # fix double-escaped backslashes (to revisit)
    request_url = 'https://' + server_name + ':3129/v1/group/path/add'
    request_headers = {'X-ApiKey': api_key}
    request_body = {'groupid': groupid,
                    'path': path}
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
    response.raise_for_status()

# Method to remove a Path Exclusion from a Policy Group
def remove_path(server_name, api_key, groupid, path):
    path = path.replace('\\\\', '\\')  # fix double-escaped backslashes (to revisit)
    request_url = 'https://' + server_name + ':3129/v1/group/path/remove'
    request_headers = {'X-ApiKey': api_key}
    request_body = {'groupid': groupid,
                    'path': path}
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
    response.raise_for_status()


## MAIN METHOD THAT GETS EXECUTED WHEN THIS SCRIPT IS RUN ##

def main():

    server_name, api_key = read_config()

    groups = get_groups(server_name, api_key)
    print(len(groups), 'groups downloaded')

    parents = get_parents(groups)
    print(len(parents), 'of those are Parent Policy Groups')

    print('Choose a Parent Policy Group to process')
    parent = choose_group(parents)
    children = get_children(groups, parent)
    print('You chose', f'{parent["name"]} ({parent["groupid"]})', 'which has', len(children), 'children')

    paths = get_paths(server_name, api_key, parent['groupid'])
    print(len(paths), 'Path Exclusions in the parent')

    print('Choose a Path Exclusion to migrate fro the parent to the children')
    path = choose_path(paths)
    print('You chose', path)

    for child in children:
        print('Adding', path, 'to', f'{child["name"]} ({child["groupid"]})')
        add_path(server_name, api_key, child['groupid'], path)
    
    print('Removing', path, 'from', f'{parent["name"]} ({parent["groupid"]})')
    remove_path(server_name, api_key, parent['groupid'], path)


# When this .py file is run directly, invoke the main method defined above
if __name__ == '__main__':
    main()