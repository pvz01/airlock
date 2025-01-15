"""
Example of how to bulk move agents to new policy groups.

Compared to move_devices.py which accepts a list of hostnames and
moves one at a time, this script (move_agents_bulk.py) takes advantage
of the bulk move capability added to the /v1/agent/move endpoint 
starting in 5.3.4 and moves agents in a configurable max_batch_size.

This script includes throttling in the form of a dynamically-calculated
sleep duration after each batch where the number of agents in the
current batch is multipled by the configured throttle_per_agent_moved
value. This is useful if you have a large number of agents to re-arrange
and you want to limit the resulting network traffic and also impact on
the server by doing a "low and slow" transition over many hours, days,
or weeks.

This script reads a list of requested moves from an XLSX or CSV, then
inspects current policy group assignment to determine which of the requested
moves have already been completed and which are needed. This can be useful
because if you need to pause the moves and modify throttle or other
configuration, you can safely kill it at any time with Ctrl+C, adjust
configuration, and restart the script. It will pick up right where it left
off.

USAGE:

To use this script, you must first create and configure two input
files which need to be placed on disk in the same directory as the PY:

1. This tool reads server configuration from a YAML configuration file.
   Use a text editor of your choice to create a configuration file matching 
   the syntax below and place it in the same folder as the PY script.
   
   server_name: foo.bar.managedwhitelisting.com
   api_key: yourapikey

   The API key provided in the YAML must have permission to the following API endpoints:
	  agent/find
	  agent/move

2. This tool reads the list of requested agent moves from an XLSX (Excel
   OOXML) or CSV file. Use Excel or equivalent to create a single sheet (tab) 
   workbook with two columns. In the first row, provide column headers, and
   in subsequent rows provide the list of requested moves. Example format:

   agentid                               groupid
   aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa  11111111-1111-1111-1111-111111111111
   bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb  11111111-1111-1111-1111-111111111111
   cccccccc-cccc-cccc-cccc-cccccccccccc  11111111-1111-1111-1111-111111111111
   dddddddd-dddd-dddd-dddd-dddddddddddd  22222222-2222-2222-2222-222222222222
   eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee  22222222-2222-2222-2222-222222222222

   Alternately, create a CSV file following the equivalent format. Example:

   agentid,groupid
   aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,11111111-1111-1111-1111-111111111111
   bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,11111111-1111-1111-1111-111111111111
   cccccccc-cccc-cccc-cccc-cccccccccccc,11111111-1111-1111-1111-111111111111
   dddddddd-dddd-dddd-dddd-dddddddddddd,22222222-2222-2222-2222-222222222222
   eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,22222222-2222-2222-2222-222222222222

   Regardless of file format, the header row is required. The columns 'agentid'
   and 'groupid' are required and their names are cASe SENsITive. No specific
   column order is required. Additional columns can be present and will have no
   effect on functionality of the script.

With the two input files in place, review the CONFIGURATION PARAMETERS section
below and provide the file name of each. You can also adjust the other parameters
to meet your needs. Keep in mind that sleep time between batches will be 
max_batch_size * throttle_per_agent_moved assuming enough needed moves exist to
fill a batch.

Save this file, then run it with this command:
python move_agents_bulk.py

Progress will be reflected in the console output, and you can cancel the job at
any point using Ctrl+C.
"""

# CONFIGURATION PARAMETERS
config_file = 'airlock.yaml'  # Name of YAML file to get server configuration
input_file = 'agent_moves.xlsx'  # Name of XLSX or CSV file to get requested moves
max_batch_size = 20  # Maximum number of agents to move in a single batch
throttle_per_agent_moved = 30  # Sleep time *per agent moved* after each batch
retry_interval = 300  # Sleep time in case of unresponsive server
max_retries = 12  # Number of retries in case of unresponsive server


# Import libraries
import requests, json, urllib3, yaml, pandas, time, sys
from datetime import datetime, timezone 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read server config from YAML
with open(config_file, 'r') as file:
    config = yaml.safe_load(file)
api_key = config['api_key']
server_name = config['server_name']
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print('Read config for server', server_name, 'from', config_file)

# Download list of agents from server
url = 'https://' + server_name + ':3129/v1/agent/find'
response = requests.post(url, json={}, headers={'X-ApiKey': api_key}, verify=False)
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print(url, response)
agents = response.json()['response']['agents']
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print(len(agents), 'agents downloaded from server')

# Create a mapping of agentid to groupid from the agents list for quick lookup
agent_group_map = {agent['agentid']: agent['groupid'] for agent in agents}

# Read list of requested moves from XLSX or CSV
if input_file[-5:].lower() == '.xlsx':
    df = pandas.read_excel(input_file)
elif input_file[-4:].lower() == '.csv':
    df = pandas.read_csv(input_file)
else:
    print(input_file, 'is not a supported file type')
    sys.exit(1)
requested_moves = df.to_dict(orient='records')
requested_move_count = len(requested_moves)
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print(requested_move_count, 'requested moves were read from', input_file)

# Compare requested moves to agent list to calculate required moves
required_moves = {}
for agent in requested_moves:
    target_groupid = agent['groupid']
    agent_id = agent['agentid']
    current_groupid = agent_group_map.get(agent_id)
    if current_groupid != target_groupid:
        if target_groupid not in required_moves:
            required_moves[target_groupid] = []
        required_moves[target_groupid].append(agent_id)
        
# Print summary of required moves
required_move_count = sum(len(ids) for ids in required_moves.values())
move_done_count = requested_move_count - required_move_count #seed this with count of requested-but-already-done moves
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print(move_done_count, 'of', requested_move_count, 'requested moves have already been completed')
print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
print(required_move_count, 'additional moves are needed')
for groupid, ids in required_moves.items():
    print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
    print(len(ids), 'moves to', groupid)

# Perform required moves
url = 'https://' + server_name + ':3129/v1/agent/move'
for groupid, agent_ids in required_moves.items():
    for i in range(0, len(agent_ids), max_batch_size):
        batch = agent_ids[i:i + max_batch_size]
        body = {'groupid': groupid, 'agentid': batch}
        attempts = 0  # Keep track of the number of attempts
        while attempts < max_retries:
            try:
                print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
                print('Attempting to move', len(batch), 'agents to', groupid)
                response = requests.post(url, json=body, headers={'X-ApiKey': api_key}, verify=False)
                if response.status_code == 200:
                    print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
                    print('Success:', url, response)
                    move_done_count += len(batch)
                    break #break out of retry loop
                else:
                    print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
                    print('Failed with status code:', response.status_code)
                    print('Request URL was', url)
                    print(f'Retry {attempts + 1}/{max_retries} after {retry_interval} seconds...')
                    time.sleep(retry_interval)
                    attempts += 1
            except requests.exceptions.RequestException as e:
                print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
                print('Error:', e)
                print(f'Retry {attempts + 1}/{max_retries} after {retry_interval} seconds...')
                time.sleep(retry_interval)
                attempts += 1
        percent_done = (move_done_count / requested_move_count) * 100
        print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
        print(move_done_count, 'of', requested_move_count, f"({percent_done:.2f}%)" , 'requested agent moves have been completed')
        sleep_time = len(batch) * throttle_per_agent_moved
        print(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), end=' ')
        print('Sleeping', sleep_time, 'seconds')
        time.sleep(sleep_time)
print('Done.')