# PVZ's Rules Based Policy Group Assignment for Airlock
# Patrick Van Zandt
#
# This is an example of how to implement dynamic Policy Group assignment based on a set of
# rules written against metadata reported by agents such as hostname or operating
# system. This can be useful if you are installing agents into a generic policy group
# or if you simply want to identify and correct incorrect policy group assignments
# that violate your defined criteria. This script runs indefinitely, checking the list
# of registered agents every 15 minutes (by default), iterating through the rules you
# define to determine which devices need to be moved, and then performing those
# moves. All interaction with the server uses the public API documented at
# https://api.airlockdigital.com/
#
# This script requires an API key for a user in a group with the following API role
# permissions:
#
#     agent/find
#     agent/move
#
# This script ingests configuration from airlock.yaml, which you must create and place in the same directory
# as this .py file. Use any text editor of your choice and follow the template below.
'''

server_name: x.y.managedwhitelisting.com
api_key: z

rules_based_policy_group_assignment:
  
  categories:
    - name: Lab Machines
      hostname_startswith: lab-
      valid_policy_groups: 
        - aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa
        - bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb
      target_policy_group: aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa

    - name: Developers
      hostname_substring: 
        start: 3
        end: 6
        match: dev
      valid_policy_groups: 
        - ccccccc3-cccc-cccc-cccc-cccccccccccc
      target_policy_group: ccccccc3-cccc-cccc-cccc-cccccccccccc

    - name: Servers
      os_contains: windows server
      valid_policy_groups: 
        - ddddddd4-dddd-dddd-dddd-dddddddddddd
        - eeeeeee5-eeee-eeee-eeee-eeeeeeeeeeee
        - fffffff6-ffff-ffff-ffff-ffffffffffff
      target_policy_group: ddddddd4-dddd-dddd-dddd-dddddddddddd

    - name: General User Population
      valid_policy_groups: 
        - ggggggg7-gggg-gggg-gggg-gggggggggggg
        - hhhhhhh8-hhhh-hhhh-hhhh-hhhhhhhhhhhh
        - iiiiiii9-iiii-iiii-iiii-iiiiiiiiiiii
        - jjjjjjj0-jjjj-jjjj-jjjj-jjjjjjjjjjjj
      target_policy_group: jjjjjjj0-jjjj-jjjj-jjjj-jjjjjjjjjjjj

'''
# For more details on the required and optional fields and syntax, reference the documentation 
# in rules_based_policy_group_assignment.md
#
# This script requires Python 3.x and several libraries. To install the libraries run this command:
#    pip install requests pyyaml


## Import required libraries ##
import requests
import yaml
import datetime
import csv
import os
import sys
from time import sleep
from requests.exceptions import RequestException


## READ AND PROCESS CONFIGURATION ##

# Load configuration from YAML
config_file_path = 'airlock.yaml'
if not os.path.exists(config_file_path):
    print('ERROR: Configuration file', config_file_path, 'does not exist')
    sys.exit(1)
print('Reading configuration from', config_file_path)
with open(config_file_path, 'r') as file:
    config = yaml.safe_load(file)

# Extract configuration parameters, using default values for any missing parameters
server_name = config['server_name']
api_key = config['api_key']
categories = config['rules_based_policy_group_assignment']['categories']
sleep_time = config['rules_based_policy_group_assignment'].get('interval_between_runs_seconds', 900)
max_batch_size = config['rules_based_policy_group_assignment'].get('max_batch_size', 100)
throttle_per_agent_moved = config['rules_based_policy_group_assignment'].get('throttle_per_agent_moved', 1)
groupids_to_move_from = config['rules_based_policy_group_assignment'].get('groupids_to_move_from', None)
output_file = config['rules_based_policy_group_assignment'].get('output_file', 'rules_based_policy_group_assignment_log.csv')
simulation_mode = config['rules_based_policy_group_assignment'].get('simulation_mode', False)


## DEFINE METHODS USED AT RUNTIME ##

# Function to initialize the CSV log file, avoiding duplicate headers
def initialize_csv():
    file_exists = os.path.isfile(output_file)
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        # Write header only if the file does not already exist
        if not file_exists:
            writer.writerow(['timestamp', 
                             'hostname', 
                             'category', 
                             'agentid', 
                             'groupid_moved_from', 
                             'groupid_moved_to',
                             'mode'  # LIVE or SIMULATED
                             ])

# Function to log moves in the CSV
def log_agent_move(agent, category, groupid_from, groupid_to):
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        mode = 'SIMULATED' if simulation_mode else 'LIVE'
        writer.writerow([timestamp, 
                         agent['hostname'], 
                         category, 
                         agent['agentid'], 
                         groupid_from, 
                         groupid_to,
                         mode])

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
    request_url = f'https://{server_name}:3129/v1/agent/move'

    # Break agents_to_move into batches
    for i in range(0, len(agents_to_move), max_batch_size):
        batch = agents_to_move[i:i + max_batch_size]
        agent_ids = [agent['agentid'] for agent in batch]
        request_body = {'groupid': target_group_id, 'agentid': agent_ids}
        
        # Move this batch        
        if not simulation_mode:
            print('Attempting to move', len(batch), 'agents starting with', agent_ids[0:2], 'to', target_group_id)
            response = requests.post(request_url, headers=request_headers, json=request_body)
            if response.status_code == 200:
                print(response)
            else:
                print('Failed:', response, response.text)
                sys.exit(1)
        else:
            print('Simulating move of', len(batch), 'agents starting with', agent_ids[0:2], 'to', target_group_id)

        # Log the moves
        for agent in batch:
            log_agent_move(agent, category_name, agent['groupid'], target_group_id)

        # Sleep before moving next batch
        if throttle_per_agent_moved > 0:
            batch_sleep = throttle_per_agent_moved * len(batch)
            print('Sleeping for', batch_sleep, 'seconds')
            sleep(batch_sleep)


## MAIN LOOP TO PROCESS AGENTS AND PERFORM ANY NECESSARY MOVES ##

# Ensure the CSV file is initialized with headers if needed
initialize_csv()

# Set the HTTP headers for API requests
request_headers = {'X-ApiKey': api_key}

# Loop indefinitely
while True:
    try:        
        # Download the list of agents from the server
        request_url = f'https://{server_name}:3129/v1/agent/find'
        response = requests.post(request_url, headers=request_headers, json={}, timeout=60)
        response.raise_for_status()  # Raise an exception for bad responses
        agents = response.json()['response']['agents']
        print(f'Found {len(agents)} total agents')

        # Apply groupid filter if configured
        if groupids_to_move_from is not None:
            print('Filter is enabled to restrict moves to agents currently in', groupids_to_move_from)
            filtered_agent_list = []
            for agent in agents:
                if agent['groupid'] in groupids_to_move_from:
                    filtered_agent_list.append(agent)
            agents = filtered_agent_list
            print(f'{len(agents)} agents remaining after applying groupid filter')

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
    sleep(sleep_time)
