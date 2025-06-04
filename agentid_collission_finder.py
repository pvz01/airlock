# agentid_collission_finder.py
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to detect and report on agentid (clientid) collission, meaning that >1 hostname
# in your environment is using the same clientid to contact the server. This can happen if
# a computer with Airlock Enforcement Agent already installed is cloned without the required
# sysprep/generalization process being followed.
#
# This script requires an API key with the following permissions:
#     agent/find
#
# The API key must be provided along with the DNS name of your Airlock Server in a
# configuration file named 'airlock.yaml'. Create this with any text editor of your
# choice and save it in the same directory as this script. Use this template:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# To install dependencies, run this command:
#     pip install requests pyyaml pandas


# CONFIGURATION

# yaml file to get Airlock server name and API key from
config_file_name = 'airlock.yaml'

# Define how many time to query the server for agent inventory. More produces better data but increases runtime.
iterations = 480

# Define how long to wait between each iteration. Less is better but increases network load. I recommend always using the default (60 seconds).
sleep_time = 60 

# Define whether the output file should include a second sheet (tab) with the "singles", meaning the devices that are not showing signs of agentid collission
include_singles = True

# Define whether to take action and clean up the duplicates by removing the associated agentids from the server
enable_remediation = True

 
# RUNTIME
 
# Import required libraries
import requests, json, yaml, time, pandas
from datetime import datetime, timezone

# Get Airlock Server config
with open(config_file_name, 'r') as file:
    config = yaml.safe_load(file)
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Read config for Airlock Server', config['server_name'], 'from', config_file_name)

# Create an dictionary to store collected data
collected_data = {}

# Define request parameters for querying the server
url = 'https://' + config['server_name'] + ':3129/v1/agent/find'
headers= {'X-ApiKey': config['api_key']}
payload = {} #empty search parameters means return all agents

# Counter used to report number of collissions which is used in console output
counter = 0

# Counter used to print out which iteration we are on
iteration_counter = 1

# Capture timestamp at start
start_time = datetime.now(timezone.utc)

while True:
 
    try:
        # Query server to get the agent list
        response = requests.post(url, headers=headers, json=payload, verify=True)
        response.raise_for_status()
        agents = response.json().get('response', {}).get('agents', [])
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), len(agents), 'agents downloaded from server on iteration', iteration_counter, 'of', iterations)

        # Process the data
        for agent in agents:
            hostname = agent['hostname']
            agentid = agent['agentid']
            if agentid not in collected_data.keys():
                collected_data[agentid] = [hostname]
            else:
                if hostname not in collected_data[agentid]:
                    collected_data[agentid].append(hostname)
                    if len(collected_data[agentid]) > 2:
                        counter += 1
                    else:
                        counter += 2
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), counter, 'total hostnames without their own unique agentid have been found')

    except requests.exceptions.RequestException as e:
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Error querying server:', e)
    
    # Increment iteration_counter
    iteration_counter += 1
    
    # Check if additional iteraitons remain, and if yes sleep before repeating
    if iteration_counter < iterations + 1:
        time.sleep(sleep_time)
    else:
        # Configurated iterations complete. Break out of while True block.
        break

# Capture timestamp at end
end_time = datetime.now(timezone.utc)

# Generate results
results = [
            {'agentid': agentid, 'hostname_count': len(hostnames), 'hostnames': ', '.join(hostnames)}
            for agentid, hostnames in collected_data.items()
]

# Convert results to to dataframe
results_df = pandas.DataFrame(results)

# Split the dataframe into two dataframes
duplicates_df = results_df[results_df['hostname_count'] > 1]
singles_df = results_df[results_df['hostname_count'] == 1]

# Sort the duplicates by hostname_count descending
duplicates_df = duplicates_df.sort_values(by='hostname_count', ascending=False)

# Build the export filename
server_alias = config['server_name'].split('.')[0]
start_timestamp = start_time.strftime("%Y-%m-%d_%H-%M_utc")
end_timestamp = end_time.strftime("%Y-%m-%d_%H-%M_utc")
duplicates_agentid_count = len(duplicates_df)
duplicates_hostname_count = duplicates_df['hostname_count'].sum()
export_filename = f'airlock_agentid_collision_report_{server_alias}_{start_timestamp}_to_{end_timestamp}_{duplicates_agentid_count}_{duplicates_hostname_count}.xlsx'
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Exporting results to', export_filename)

# Export the split DataFrames to Excel
with pandas.ExcelWriter(export_filename) as writer:
    duplicates_df.to_excel(writer, sheet_name='duplicates', index=False)
    if include_singles:
        singles_df.to_excel(writer, sheet_name='singles', index=False)

# Remove offending agentid values if remediation is enabled
if enable_remediation:
    
    agentid_list = duplicates_df['agentid'].dropna().tolist()
    
    if len(agentid_list) > 0:
        batch_size = 10
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Remediation is enabled. Proceeding with removal of', len(agentid_list), 'agentids from the server in batches of', batch_size, '.')
        url = 'https://' + config['server_name'] + ':3129/v1/agent/remove'
        
        for i in range(0, len(agentid_list), batch_size):
            batch = agentid_list[i:i + batch_size]
            payload = {'agentid': batch}
            time.sleep(1)
            print(datetime.now(timezone.utc).strftime("%H:%M:%S"), f'Requesting removal of {len(batch)} agentids:', batch)
            response = requests.post(url, headers=headers, json=payload, verify=True)
            print(datetime.now(timezone.utc).strftime("%H:%M:%S"), response, response.text)

print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Done.')