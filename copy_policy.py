# copy_policy.py
# Last updated: 2025-02-18
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to copy policy components from one Policy Group to another.
#
# Known limitations:
# 1. Group Settings copy is not yet implemented and will be skipped at runtime.
# 2. This script is a additive one-way sync only. It is designed to add "missing" 
#    elements (those present in the source but not the destination) to the destination,
#    but it will never delete any data, such as extra elements present in the
#    destination. To use it to create an identical copy of an existing policy group,
#    ensure that you are starting with a new blank policy group to use as the
#    destination.
# 3. A blocklist enabled in both the source and destination in two different modes
#    (one Audit and one Enforced) will be treated as "missing" and the destination
#    policy group configuration for that blocklist will be modified to match the source
#    group policy's configuration of that blocklist.
# 4. Every policy element is copied 1 at a time. At scale, this can lead to a long runtime
#    and also introduce load on the server due to multiple dbgenerate jobs.
# 
# Requires an API key with permission to the following API endpoints:
#   group
#   group/policies
#   group/baseline/approve
#   group/application/approve
#   group/blocklist/approve
#   group/path/add
#   group/publisher/add
#   group/process/add
#   group/settings/updateall


# CONFIGURATION

# Define which policy components to copy
policy_components_to_copy = {
    'baselines': True,
    'allowlists': True,
    'blocklists': True,
    'paths': True,
    'publishers': True,
    'pprocesses': True, #Trusted Parent processes
    'gprocesses': True, #Trusted GrandParent processes
    'group_settings': True
}

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

# Setting this to True will skip the "are you sure" prompts, which can be useful
# if you are running this script unattended. For ad-hoc or interactive usage,
# I recommend to leave this set to False, meaning you will be prompted before
# changes are made.
skip_sanity_check_prompt = False

# RUNTIME

# Import required libaries
import requests, json, yaml, sys, urllib3, urllib.parse

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
response = requests.post(url, headers=headers)
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

print('\nBeginning copy of policy components based on this configuration:\n', json.dumps(policy_components_to_copy, indent=4))

#print('\nYou chose to copy policy from\n', source_group, '\nto\n', destination_group)

# Get policy for source
print('\nGetting policy for the source policy group', f"'{source_group['name']}'")
url = base_url + 'group/policies?groupid=' + source_group['groupid']
response = requests.post(url, headers=headers)
print(url, response)
source_group_policy = response.json()['response']
#print(json.dumps(source_group_policy, indent=4))

# Get policy for destination
print('\nGetting policy for the destination policy group', f"'{destination_group['name']}'")
url = base_url + 'group/policies?groupid=' + destination_group['groupid']
response = requests.post(url, headers=headers)
print(url, response)
destination_group_policy = response.json()['response']
#print(json.dumps(destination_group_policy, indent=4))

if policy_components_to_copy['baselines']:
    
    # Extract Baseline list from each of the downloaded policies
    print('\nExtracting the list of approved Baselines from each of the downloaded policies')
    if source_group_policy.get('baselines') is not None:
        source_group_baseline_list = source_group_policy.get('baselines')
    else:
        source_group_baseline_list = []
    if destination_group_policy.get('baselines') is not None:
        destination_group_baseline_list = destination_group_policy.get('baselines')
    else:
        destination_group_baseline_list = []
    print(len(source_group_baseline_list), 'baselines are approved in the source policy group', f"'{source_group['name']}'")
    print(len(destination_group_baseline_list), 'baselines are approved in the destination policy group', f"'{destination_group['name']}'")

    # Compare Baseline lists
    print('\nComparing the two approved Baselines lists')
    baselines_in_both = []
    baselines_in_source_only = []
    baselines_in_destination_only = []
    for baseline in source_group_baseline_list:
        if baseline in destination_group_baseline_list:
            baselines_in_both.append(baseline)
        else:
            baselines_in_source_only.append(baseline)
    for baseline in destination_group_baseline_list:
        if baseline not in source_group_baseline_list:
            baselines_in_destination_only.append(baseline)
    print(len(baselines_in_both), 'baselines are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
    print(len(baselines_in_destination_only), 'baselines are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
    print(len(baselines_in_source_only), 'baselines are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')
    for baseline in baselines_in_source_only:
        print(baseline['baselineid'], baseline['name'])

    # Add the missing baselines to the destination policy group
    if len(baselines_in_source_only) > 0:
        # Sanity check
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(baselines_in_source_only)} baselines to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(baselines_in_source_only), 'baselines to the destination policy group', f"'{destination_group['name']}'")
                for baseline in baselines_in_source_only:
                    url = base_url + 'group/baseline/approve?groupid=' + destination_group['groupid'] + '&baselineid=' + baseline['baselineid']
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo baselines to copy')    
    print('\nBaselines are done')

if policy_components_to_copy['allowlists']:
    
    # Extract allowlist list from each of the downloaded policies
    print('\nExtracting the list of approved allowlists from each of the downloaded policies')
    if source_group_policy.get('applications') is not None:
        source_group_allowlist_list = source_group_policy.get('applications')
    else:
        source_group_allowlist_list = []
    if destination_group_policy.get('applications') is not None:
        destination_group_allowlist_list = destination_group_policy.get('applications')
    else:
        destination_group_allowlist_list = []
    print(len(source_group_allowlist_list), 'allowlists are approved in the source policy group', f"'{source_group['name']}'")
    print(len(destination_group_allowlist_list), 'allowlists are approved in the destination policy group', f"'{destination_group['name']}'")

    # Compare allowlist lists
    print('\nComparing the two approved allowlists lists')
    allowlists_in_both = []
    allowlists_in_source_only = []
    allowlists_in_destination_only = []
    for allowlist in source_group_allowlist_list:
        if allowlist in destination_group_allowlist_list:
            allowlists_in_both.append(allowlist)
        else:
            allowlists_in_source_only.append(allowlist)
    for allowlist in destination_group_allowlist_list:
        if allowlist not in source_group_allowlist_list:
            allowlists_in_destination_only.append(allowlist)
    print(len(allowlists_in_both), 'allowlists are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
    print(len(allowlists_in_destination_only), 'allowlists are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
    print(len(allowlists_in_source_only), 'allowlists are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')
    for allowlist in allowlists_in_source_only:
        print(allowlist['applicationid'], allowlist['name'], allowlist['version'])

    # Add the missing allowlists to the destination policy group
    if len(allowlists_in_source_only) > 0:
        # Sanity check
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(allowlists_in_source_only)} allowlists to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(allowlists_in_source_only), 'allowlists to the destination policy group', f"'{destination_group['name']}'")
                for allowlist in allowlists_in_source_only:
                    url = base_url + 'group/application/approve?groupid=' + destination_group['groupid'] + '&applicationid=' + allowlist['applicationid']
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo allowlists to copy')
    
    print('\nAllowlists are done')


if policy_components_to_copy['blocklists']:
    
    # Extract blocklist list from each of the downloaded policies
    print('\nExtracting the list of enabled blocklists from each of the downloaded policies')
    if source_group_policy.get('blocklists') is not None:
        source_group_blocklist_list = source_group_policy.get('blocklists')
    else:
        source_group_blocklist_list = []
    if destination_group_policy.get('blocklists') is not None:
        destination_group_blocklist_list = destination_group_policy.get('blocklists')
    else:
        destination_group_blocklist_list = []
    print(len(source_group_blocklist_list), 'blocklists are enabled in the source policy group', f"'{source_group['name']}'")
    print(len(destination_group_blocklist_list), 'blocklists are enabled in the destination policy group', f"'{destination_group['name']}'")

    # Compare blocklist lists
    print('\nComparing the two blocklists lists')
    blocklists_in_both = []
    blocklists_in_source_only = []
    blocklists_in_destination_only = []
    for blocklist in source_group_blocklist_list:
        if blocklist in destination_group_blocklist_list:
            blocklists_in_both.append(blocklist)
        else:
            blocklists_in_source_only.append(blocklist)
    for blocklist in destination_group_blocklist_list:
        if blocklist not in source_group_blocklist_list:
            blocklists_in_destination_only.append(blocklist)
    print(f"\n{len(blocklists_in_both)} blocklists are enabled and in the same mode in both policy groups ('{source_group['name']}' and '{destination_group['name']}'). Details:")
    for blocklist in blocklists_in_both:
        if str(blocklist['audit']) == '1':
            blocklist_mode = 'Audit'
        elif str(blocklist['audit']) == '0':
            blocklist_mode = 'Enforced'
        else:
            blocklist_mode = 'Unknown'
        print(blocklist['name'], f"[{blocklist_mode}]")
    print(f"\n{len(blocklists_in_destination_only)} blocklists are enabled in the destination '{destination_group['name']}' but not the source '{source_group['name']}', or alternately are enabled in different modes. Details:")
    for blocklist in blocklists_in_destination_only:
        if str(blocklist['audit']) == '1':
            blocklist_mode = 'Audit'
        elif str(blocklist['audit']) == '0':
            blocklist_mode = 'Enforced'
        else:
            blocklist_mode = 'Unknown'
        print(blocklist['name'], f"[{blocklist_mode}]")
    print(f"\n{len(blocklists_in_source_only)} blocklists are enabled in the source '{source_group['name']}' but not the destination '{destination_group['name']}', or alternately are enabled in different modes. Details:")
    for blocklist in blocklists_in_source_only:
        if str(blocklist['audit']) == '1':
            blocklist_mode = 'Audit'
        elif str(blocklist['audit']) == '0':
            blocklist_mode = 'Enforced'
        else:
            blocklist_mode = 'Unknown'
        print(blocklist['name'], f"[{blocklist_mode}]")

    # Add the missing blocklists to the destination policy group
    if len(blocklists_in_source_only) > 0:
        # Sanity check
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo apply these {len(blocklists_in_source_only)} blocklists to '{destination_group['name']}' in the mode printed above, type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(blocklists_in_source_only), 'blocklists to the destination policy group', f"'{destination_group['name']}'")
                for blocklist in blocklists_in_source_only:
                    url = base_url + 'group/blocklist/approve?groupid=' + destination_group['groupid'] + '&blocklistid=' + blocklist['blocklistid'] + '&audit=' + str(blocklist['audit'])
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo blocklists to copy')    
    print('\nBlocklists are done')


if policy_components_to_copy['paths']:

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

    # Add the missing paths to the destination policy group
    if len(paths_in_source_only) > 0:
            # Sanity check
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(paths_in_source_only)} paths to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(paths_in_source_only), 'paths to the destination policy group', f"'{destination_group['name']}'")
                for path in paths_in_source_only:
                    path = path.replace('\\\\', '\\')
                    encoded_path = urllib.parse.quote(path)
                    url = base_url + 'group/path/add?groupid=' + destination_group['groupid'] + "&path=" + encoded_path
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo paths to copy')
    
    print('\nPath Exclusions are done')

if policy_components_to_copy['publishers']:

    # Extract Trusted Publishers list from each of the downloaded policies
    print('\nExtracting the list Trusted Publishers from each of the downloaded policies')
    if source_group_policy.get('publishers') is not None:
        source_group_publisher_list = [publisher['name'] for publisher in source_group_policy['publishers']]
    else:
        source_group_publisher_list = []
    if destination_group_policy.get('publishers') is not None:
        destination_group_publisher_list = [publisher['name'] for publisher in destination_group_policy['publishers']]
    else:
        destination_group_publisher_list = []
    print(len(source_group_publisher_list), 'trusted publishers are in the source policy group', f"'{source_group['name']}'")
    print(len(destination_group_publisher_list), 'trusted publishers are in the destination policy group', f"'{destination_group['name']}'")

    # Compare publisher Exclusion lists
    print('\nComparing the two Trusted Publisher lists')
    publishers_in_both = []
    publishers_in_source_only = []
    publishers_in_destination_only = []
    for publisher in source_group_publisher_list:
        if publisher in destination_group_publisher_list:
            publishers_in_both.append(publisher)
        else:
            publishers_in_source_only.append(publisher)
    for publisher in destination_group_publisher_list:
        if publisher not in source_group_publisher_list:
            publishers_in_destination_only.append(publisher)
    print(len(publishers_in_both), 'trusted publishers are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
    print(len(publishers_in_destination_only), 'trusted publishers are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
    print(len(publishers_in_source_only), 'trusted publishers are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')

    # Add the missing trusted publishers to the destination policy group
    if len(publishers_in_source_only) > 0:
        # Sanity check
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(publishers_in_source_only)} trusted publishers to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(publishers_in_source_only), 'trusted publishers to the destination policy group', f"'{destination_group['name']}'")
                for publisher in publishers_in_source_only:
                    encoded_publisher = urllib.parse.quote(publisher)
                    url = base_url + 'group/publisher/add?groupid=' + destination_group['groupid'] + "&publisher=" + encoded_publisher
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo trusted publishers to copy')
    
    print('\nTrusted Publishers are done')


if policy_components_to_copy['pprocesses']:
    print('\nExtracting the list of Trusted Parent Processes (pprocesses) from each of the downloaded policies')
    if source_group_policy.get('pprocesses') is not None:
        source_group_pprocesses_list = [process['name'] for process in source_group_policy['pprocesses']]
    else:
        source_group_pprocesses_list = []
    if destination_group_policy.get('pprocesses') is not None:
        destination_group_pprocesses_list = [process['name'] for process in destination_group_policy['pprocesses']]
    else:
        destination_group_pprocesses_list = []

    print('\nComparing the two Trusted Parent Processes lists')
    pprocesses_in_both = []
    pprocesses_in_source_only = []
    pprocesses_in_destination_only = []
    for process in source_group_pprocesses_list:
        if process in destination_group_pprocesses_list:
            pprocesses_in_both.append(process)
        else:
            pprocesses_in_source_only.append(process)
    for process in destination_group_pprocesses_list:
        if process not in source_group_pprocesses_list:
            pprocesses_in_destination_only.append(process)
    print(len(pprocesses_in_both), 'Trusted Parent Processes are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
    print(len(pprocesses_in_destination_only), 'Trusted Parent Processes are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
    print(len(pprocesses_in_source_only), 'Trusted Parent Processes are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')
    for process in pprocesses_in_source_only:
        print(process.replace('\\\\', '\\'))

    if len(pprocesses_in_source_only) > 0:
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(pprocesses_in_source_only)} Trusted Parent Processes to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(pprocesses_in_source_only), 'Trusted Parent Processes to the destination policy group', f"'{destination_group['name']}'")
                for process in pprocesses_in_source_only:
                    process = process.replace('\\\\', '\\')
                    encoded_process = urllib.parse.quote(process)
                    url = base_url + 'group/process/add?type=pprocess&groupid=' + destination_group['groupid'] + "&process=" + encoded_process
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo pprocesses to copy')

    print('\nTrused Parent Processes are done')

if policy_components_to_copy['gprocesses']:
    print('\nExtracting the list of Trusted Grandparent Processes (gprocesses) from each of the downloaded policies')
    if source_group_policy.get('gprocesses') is not None:
        source_group_gprocesses_list = [process['name'] for process in source_group_policy['gprocesses']]
    else:
        source_group_gprocesses_list = []
    if destination_group_policy.get('gprocesses') is not None:
        destination_group_gprocesses_list = [process['name'] for process in destination_group_policy['gprocesses']]
    else:
        destination_group_gprocesses_list = []

    print('\nComparing the two Trusted Grandparent Processes lists')
    gprocesses_in_both = []
    gprocesses_in_source_only = []
    gprocesses_in_destination_only = []
    for process in source_group_gprocesses_list:
        if process in destination_group_gprocesses_list:
            gprocesses_in_both.append(process)
        else:
            gprocesses_in_source_only.append(process)
    for process in destination_group_gprocesses_list:
        if process not in source_group_gprocesses_list:
            gprocesses_in_destination_only.append(process)
    print(len(gprocesses_in_both), 'Trusted Grandparent Processes are in both policy groups', f"('{source_group['name']}'", 'and', f"'{destination_group['name']}')")
    print(len(gprocesses_in_destination_only), 'Trusted Grandparent Processes are in the destination', f"'{destination_group['name']}'", 'but not the source', f"'{source_group['name']}'")
    print(len(gprocesses_in_source_only), 'Trusted Grandparent Processes are in the source', f"'{source_group['name']}'", 'but not destination', f"'{destination_group['name']}'", '\n')
    for process in gprocesses_in_source_only:
        print(process.replace('\\\\', '\\'))

    if len(gprocesses_in_source_only) > 0:
        if skip_sanity_check_prompt:
            print('\nSkipping sanity check based on configuration')
        else:
            user_response = input(f"\nTo add these {len(gprocesses_in_source_only)} Trusted Grandparent Processes to '{destination_group['name']}' type PROCEED and press return: ")
            if user_response == 'PROCEED':
                print('Proceeding based on your response:', user_response)
                print('\nAdding', len(gprocesses_in_source_only), 'Trusted Grandparent Processes to the destination policy group', f"'{destination_group['name']}'")
                for process in gprocesses_in_source_only:
                    process = process.replace('\\\\', '\\')
                    encoded_process = urllib.parse.quote(process)
                    url = base_url + 'group/process/add?type=gprocess&groupid=' + destination_group['groupid'] + "&process=" + encoded_process
                    response = requests.post(url, headers=headers)
                    print(url, response)
            else:
                print('Aborting change based on our response:', user_response)
    else:
        print('\nNo gprocesses to copy')
    
    print('\nTrused Grandparent Processes are done')

if policy_components_to_copy['group_settings']:
    print('\nGroup Settings copy is enabled but not yet implemented')
    pass #not yet implemented

print('\nDone')