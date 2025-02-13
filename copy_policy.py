# Example of how to copy policy from one policy group to another. In this initial
# version only Path Exclusions are copied, but it can be extended to copy additional
# data types.
# 
# Requires an API key with permission to the following API endpoints:
#   group
#   group/policies
#   group/path/add


# CONFIGURATION

# Name of file containing Airlock Server configuration. Create in a text editor
# of your choice following this template:
'''
server_name: foo
api_key: bar
'''
config_file_name = 'airlock.yaml'

# OPTIONAL - Provide policy group names to copy from and/or to. If you leave
# this blank or provide a string that does not match the name of a policy group
# on your server at the time the script is run, you will be prompted to choose
# the group or groups interactively at runtime.
source_policy_group_name = ''
destination_policy_group_name = ''

# Setting this to True will skip the "are you sure" prompt, which can be useful
# if you are running this script unattended. For ad-hoc or interactive usage,
# I recomment to leave this set to False.
skip_sanity_check_prompt = False

# RUNTIME

# Import required libaries
import requests, json, yaml, sys, urllib3, urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read Airlock Server configuration from YAML on disk
print('\nReading configuration from', config_file_name)
with open(config_file_name, 'r') as file:
    config = yaml.safe_load(file)

# Validate configuration
server_name = config.get('server_name', None)
if not server_name:
    print('Error: server_name is missing in the config file')
    sys.exit(1)
else:
    print('Read server_name', server_name)

api_key = config.get('api_key', None)
if not api_key:
    print('Error: api_key is missing in the config file')
    sys.exit(1)
print(f"Read api_key {'*' * (len(api_key) - 4)}{api_key[-4:]}")

# Calculate base configuration for interacting with Airlock Server
base_url = f"https://{server_name}:3129/v1/"
headers = {'X-ApiKey': api_key}

# Get Policy Groups list
print('\nGetting list of Policy Groups')
url = base_url + 'group'
response = requests.post(url, headers=headers, verify=False)
print(url, response)
groups = response.json()['response']['groups']
print()
print(len(groups), 'Policy Groups downloaded from server')

# Create a dictionary to map GUID (groupid) to human-readable name
group_mapping = {group['groupid']: group['name'] for group in groups}

# Prepend parent name to the human-readable names
for group in groups:
    parent_name = group_mapping.get(group['parent'])
    if parent_name:
        group['name'] = f"{parent_name}\\{group['name']}"

# Choose source and destination groups
source_group = None
destination_group = None
for index, item in enumerate(groups):
    print(f'{index+1}: {item["name"]}')
    if item['name'] == source_policy_group_name:
        source_group = item
    if item['name'] == destination_policy_group_name:
        destination_group = item
if source_group is None:
    source_index = int(input('\nWhich policy group do you want to copy policy from? '))-1
    source_group = groups[source_index]
print('\nPolicy will be copied from', f"'{source_group['name']}'")
if destination_group is None:
    source_index = int(input('\nWhich policy group do you want to copy policy to? '))-1
    destination_group = groups[source_index]
print('\nPolicy will be copied to', f"'{destination_group['name']}'")
#print('\nYou chose to copy policy from\n', source_group, '\nto\n', destination_group)

# Get policy for source
print('\nGetting policy for the source policy group', f"'{source_group['name']}'")
url = base_url + 'group/policies?groupid=' + source_group['groupid']
response = requests.post(url, headers=headers, verify=False)
print(url, response)
source_group_policy = response.json()['response']
#print(json.dumps(source_group_policy, indent=4))

# Get policy for destination
print('\nGetting policy for the destination policy group', f"'{destination_group['name']}'")
url = base_url + 'group/policies?groupid=' + destination_group['groupid']
response = requests.post(url, headers=headers, verify=False)
print(url, response)
destination_group_policy = response.json()['response']
#print(json.dumps(destination_group_policy, indent=4))

# Extract Path Exclusion list from each of the downloaded policies
print('\nExtracting the list of path exclusions from each of the downloaded policies')
if source_group_policy.get('paths') is not None:
    source_group_path_list = [path['name'] for path in source_group_policy['paths']]
else:
    source_group_path_list = []
if destination_group_policy.get('paths') is not None:
    destination_group_path_list = [path['name'] for path in destination_group_policy['paths']]
else:
    destination_group_path_list = []
print(len(source_group_path_list), 'paths are in the source policy group', f"'{source_group['name']}'")
print(len(destination_group_path_list), 'paths are in the destination policy group', f"'{destination_group['name']}'")

# Compare Path Exclusion lists
print('\nComparing the two path exclusion lists')
paths_in_both = []
paths_in_source_only = []
paths_in_destination_only = []
for path in source_group_path_list:
    if path in destination_group_path_list:
          paths_in_both.append(path)
    else:
          paths_in_source_only.append(path)
for path in destination_group_path_list:
    if path not in source_group_path_list:
          paths_in_destination_only.append(path)
print(len(paths_in_both), 'paths are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
print(len(paths_in_destination_only), 'paths are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
print(len(paths_in_source_only), 'paths are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')
for path in paths_in_source_only:
    print(path.replace('\\\\', '\\'))

# Sanity check
if skip_sanity_check_prompt:
    print('\nSkipping sanity check based on configuration')
else:
    user_response = input(f"\nTo add these {len(paths_in_source_only)} paths to '{destination_group['name']}' type PROCEED and press return: ")
    if user_response == 'PROCEED':
        print('Proceeding based on your response:', user_response)
    else:
        print('Aborting change based on our response:', user_response)
        sys.exit(1)

# Add the missing paths to the destination policy group
if len(paths_in_source_only) > 0:
    print('\nAdding', len(paths_in_source_only), 'paths to the destination policy group', f"'{destination_group['name']}'")
    for path in paths_in_source_only:
        path = path.replace('\\\\', '\\')
        encoded_path = urllib.parse.quote(path)
        url = base_url + 'group/path/add?groupid=' + destination_group['groupid'] + "&path=" + encoded_path
        response = requests.post(url, headers=headers, verify=False)
        print(url, response)
else:
    print('\nNo paths to copy')

print('\nDone')