# export_events.py
# Version: 1.0
# Last updated: 2024-01-16
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

'''This is an example of how to query the server for event data using the Airlock API,
de-duplicate it based on file hash, and then write the results to disk in Excel format
using Pandas. This script requires a YAML configuration file. Create the YAML using the
template provided and then enter the relative or absolute path to the YAML below.'''

config_file = 'export_events.yaml'

'''
# Required
server_name: your-airlock-server
api_key: your-airlock-api-key
unique_files_only: true

# Optional
start_date: 2023-01-01
end_date: 2023-12-31
#policy_name: Workstations Audit Mode
#parent_policy_name: Workstations
event_type: audit
#event_type: blocked
#event_type: otp
#event_type: blocklist
#event_type: blocklist audit
#event_type: trusted
#event_type: trusted publisher
#event_type: trusted path
''' 

# -- IMPORT REQUIRED LIBRARIES --
import requests
import yaml
import datetime
import urllib3
import pandas
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #suppress ssl warnings

# Read YAML config file from disk
print('Reading configuration from', config_file)
with open(config_file, 'r') as file:
    config = yaml.safe_load(file)

# Calculate parameters for request
url = 'https://' + config['server_name'] + ':3129/v1/getexechistory'
headers = {'X-APIKey': config['api_key']}
body = {}
if 'start_date' in config.keys():
    body['Datefrom'] = config['start_date'].isoformat()
if 'end_date' in config.keys():
    body['Dateto'] = config['end_date'].isoformat()
if 'event_type' in config.keys():
    body['Category'] = config['event_type']
if 'policy_name' in config.keys():
    body['Policyname'] = config['policy_name']
if 'parent_policy_name' in config.keys():
    body['Ppolicy'] = config['parent_policy_name']

# Get event data from server
print('Making request to server with these parameters')
print('URL:    ', url)
print('HEADERS:', headers)
print('BODY:   ', body)
response = requests.post(url, headers=headers, json=body, verify=False)
print(response)
exechistory = response.json()['response']['exechistory']
print(len(exechistory), 'records returned')

# De-duplicate data based on file hash
if config['unique_files_only']:
    unique_events = {}
    for event in exechistory:
        sha256 = event['sha256']
        if sha256 not in unique_events:
            unique_events[sha256] = event
    exechistory = list(unique_events.values())
    print(len(exechistory), 'records remain after de-duplication')

# Export data to disk
file_name = f"airlock_events_{config['server_name'].replace('.','-')}_{datetime.datetime.today().strftime('%Y-%m-%d_%H.%M')}.xlsx"
print('Exporting data to', file_name)
exechistory_df = pandas.DataFrame(exechistory)
exechistory_df.to_excel(file_name, index=False)
