# rule_based_policy_group_assignment.py
# Version: 1.0
# Last updated: 2024-10-25
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to implement dynamic Policy Group assignment based on a set of
# rules written against metadata reported by agents such as hostname or operating
# system. This can be useful if you are installing agents into a generic policy group
# or if you simply want to identify and correct incorrect policy group assignments
# that violate your defined criteria. This script runs indefinitely, checking the list
# of registered agents every 15 minutes (by default), iterate through the rules you
# define to determine which devices need to be moved, and then performing those
# moves. All interaction with the server uses the public API documented at
# https://api.airlockdigital.com/
#
# This script requires an API key for a user in a group with the following API role
# permissions:
#     agent/find
#     agent/move
#
# This script ingests configuration from a YAML file. For details on the required
# fields and syntax, reference the documentation in
# rule_based_policy_group_assignment.md


import requests, json, urllib3, yaml, datetime, time, csv, os
from requests.exceptions import RequestException
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load the YAML configuration
with open('airlock.yaml', 'r') as file:
    config = yaml.safe_load(file)

# Extract configuration values
server_name = config['server_name']
api_key = config['api_key']
sleep_time = config['rules_based_policy_group_assignment']['interval_between_runs_seconds']
categories = config['rules_based_policy_group_assignment']['categories']
output_file = config['rules_based_policy_group_assignment'].get('output_file', 'rules_based_policy_group_assignment_log.csv')

# Set the HTTP headers for API requests
request_headers = {'X-ApiKey': api_key}

# Initialize the CSV file, avoiding duplicate headers
def initialize_csv():
    file_exists = os.path.isfile(output_file)
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        # Write header only if the file does not already exist
        if not file_exists:
            writer.writerow(['timestamp', 'hostname', 'category', 'agentid', 'groupid_moved_from', 'groupid_moved_to'])

# Function to log moves in the CSV
def log_agent_move(agent, category, groupid_from, groupid_to):
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        writer.writerow([timestamp, agent['hostname'], category, agent['agentid'], groupid_from, groupid_to])

# Main function to categorize agents based on the YAML rules
def categorize_agents(agent):
    hostname = agent['hostname'].lower()
    os_name = agent['os'].lower()
    
    # Loop through categories and assign agent to the first matching category
    for category in categories:
        # Check by hostname starts with, contains, or ends with
        if 'hostname_startswith' in category and hostname.startswith(category['hostname_startswith']):
            return category['name']
        if 'hostname_contains' in category and category['hostname_contains'] in hostname:
            return category['name']
        if 'hostname_endswith' in category and hostname.endswith(category['hostname_endswith']):
            return category['name']
        
        # Check for substring at specific index range
        if 'hostname_substring' in category:
            start_idx = category['hostname_substring']['start']
            end_idx = category['hostname_substring']['end']
            substring_match = category['hostname_substring']['match']
            
            # Check if the substring in the specified range matches
            if hostname[start_idx:end_idx] == substring_match:
                return category['name']
        
        # Check by operating system (os_contains)
        if 'os_contains' in category and category['os_contains'] in os_name:
            return category['name']
    
    # Default to "Standard" category
    return 'Standard'

# Function to determine if an agent needs to be moved to a target group
def should_move(agent, category_config):
    return agent['groupid'] not in category_config['valid_policy_groups']

# Function to move agents to the correct policy group
def move_agents(agents_to_move, target_group_id, category_name):
    counter = 1
    for agent in agents_to_move:
        print(f'{counter} of {len(agents_to_move)}: Moving agent {agent["hostname"]}')
        groupid_from = agent['groupid']
        request_url = f'https://{server_name}:3129/v1/agent/move?agentid={agent["agentid"]}&groupid={target_group_id}'
        try:
            response = requests.post(request_url, headers=request_headers, verify=False, timeout=15)
            response.raise_for_status()
            print(f'Moved agent to {target_group_id} successfully.')
            log_agent_move(agent, category_name, groupid_from, target_group_id)
        except RequestException as e:
            print(f"Failed to move agent {agent['hostname']}: {e}")
        counter += 1

# Main loop to process agents
initialize_csv()  # Ensure the CSV file is initialized with headers if needed
while True:
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Download the list of agents from the server
        request_url = f'https://{server_name}:3129/v1/agent/find'
        response = requests.post(request_url, headers=request_headers, json={}, verify=False, timeout=60)
        response.raise_for_status()  # Raise an exception for bad responses

        agents = response.json()['response']['agents']
        print(f'Found {len(agents)} total agents.')

        # Categorize agents based on rules
        for agent in agents:
            agent['category'] = categorize_agents(agent)

        # Lists of agents to move
        agents_to_move_by_category = {category['name']: [] for category in categories}

        # Determine which agents need to be moved
        for agent in agents:
            for category in categories:
                if agent['category'] == category['name'] and should_move(agent, category):
                    agents_to_move_by_category[category['name']].append(agent)
        
        # Move agents in each category
        for category in categories:
            category_name = category['name']
            target_policy_group = category['target_policy_group']
            agents_to_move = agents_to_move_by_category[category_name]
            
            print(f'Found {len(agents_to_move)} agents to move to {category_name}')
            move_agents(agents_to_move, target_policy_group, category_name)

    except RequestException as e:
        # Handle any kind of request exception (e.g., network errors, timeouts)
        print(f"Request failed: {e}")
    
    # Sleep between iterations
    print(f'Sleeping for {sleep_time} seconds...')
    time.sleep(sleep_time)
