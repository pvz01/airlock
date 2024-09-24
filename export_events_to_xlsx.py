# export_events_to_xlsx.py
# Version: 1.0
# Last updated: 2024-09-24
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

import requests, json, urllib3, datetime, yaml, pandas
from datetime import datetime, timedelta
from bson import ObjectId
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(config_file_name):
    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', config_file_name, 'for server', config['server_name'])
    return config

def objectid_n_hours_ago(n):
    datetime_n_hours_ago = datetime.now() - timedelta(hours=n)
    print('Calculating objectid for', datetime_n_hours_ago)
    timestamp = int(datetime_n_hours_ago.timestamp())
    objectid_hex = hex(timestamp)[2:] + '0000000000000000'
    return ObjectId(objectid_hex)

def get_events(config):
    collected_events = []
    request_url = 'https://' + config['server_name'] + ':3129/v1/logging/exechistories'
    request_headers = {'X-ApiKey': config['api_key']}
    request_body = {'type': config['event_types']}

    while True:
        #get next (up to) 10K events from server
        request_body['checkpoint'] = config['checkpoint']
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
        events = response.json()['response']['exechistories']
        print(request_url, 'checkpoint >', request_body['checkpoint'], 'returned', len(events), 'records')
        #check if any events were returned
        if len(events) > 0:
            #increment the checkpoint using value from last event
            config['checkpoint'] = events[len(events)-1]['checkpoint']
            #append new events to list of collected events
            collected_events += events
            #less than 10K events means this was the last batch (page)
            if len(events) < 10000:
                break
        #no events returned means we already got the last batch (page)
        else:
            break

    print(len(collected_events), 'total events were downloaded')
    return collected_events

def main():

    readme_message = """
Welcome to the PVZ's Bulk Event Export script. This is an example of how to bulk export execution events
to disk in Excel OOXML format (.xlsx). To accomplish this, the script downloads the events from the server,
loads them into a Pandas DataFrame, then exports the DataFrame to disk.

To apply filtering, de-duplication, or other transforms on the data after it is downloaded from Airlock
but before it is written to disk, open the script in a text editor of your choice and reference the in-line
examples along with Pandas DataFrame documentation here: 
https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.drop.html

This script makes no changes. It is a data extract tool only.

This script reads server configuration from a YAML configuration file. Use any text editor to create a 
configuration file with the syntax below, and place it in the same folder as this Python script.

server_name: foo.bar.managedwhitelisting.com
api_key: your-api-key
event_types:
  - 0  #Trusted Execution
  - 1  #Blocked Execution
  - 2  #Untrusted Execution [Audit]
  - 3  #Untrusted Execution [OTP]
  - 4  #Trusted Path Execution
  - 5  #Trusted Publisher Execution
  - 6  #Blocklist Execution
  - 7  #Blocklist Execution [Audit]
  - 8  #Trusted Process Execution

The API key provided in the YAML must have permission to the following API endpoint(s):
	logging/exechistories

This script is published under the GNU General Public License v3.0 and is intended as a working example 
of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

	"""
    print(readme_message)

    # Get configuration from a YAML on disk
    config_file_name = input('Enter the name of a YAML file containing server configuration, or press return to accept default (airlock.yaml): ')
    if config_file_name == '':
        config = read_config('airlock.yaml')
    else:
        config = read_config(config_file_name)

    # Ask how far back to look at events
    days = int(input('How many days worth of events do you want to export? '))
    hours = 24 * days

    # Calculate a MongoDB ObjectId which is used as database checkpoint to download events
    print('Calculating database checkpoint for exporting events')
    objectid = objectid_n_hours_ago(hours)
    print('Earliest possible checkpoint for exactly', hours, 'hours ago:', objectid)
    config['checkpoint'] = str(objectid)
    
    # Download the events
    print('Getting events from server')
    events = get_events(config)

    # Load the events into a DataFrame
    print('Loading events into a DataFrame')
    events_df = pandas.DataFrame(events)
    print(len(events_df), 'rows are in DataFrame')

    # Manipulate the events in the DataFrame
    #
    # TODO: Add or adjust filtering here. Some examples below.
    #
    # Example 1: filter on file name ends with .exe
    print('Removing all except .exe files')
    events_df = events_df[events_df['filename'].str.lower().str.endswith('.exe')]
    print(len(events_df), 'rows are in DataFrame')
    #
    # Example 2: de-duplicate based on sha256, keeping only the first occurrence of each hash
    print('De-duplicating based on file hash (sha256)')
    events_df = events_df.drop_duplicates(subset='sha256', keep='first')
    print(len(events_df), 'rows are in DataFrame')
            
    # Calculate file name for export
    server_alias = config['server_name'].split('.')[0]
    timestamp = datetime.today().strftime('%Y-%m-%d_%H.%M')
    file_name = 'airlock_events_' + server_alias + '_' + timestamp + '_last_' + str(days) + '_days.xlsx'
    print('Exporting', len(events_df), 'events to', file_name)

    # Write data to disk
    events_df.to_excel(file_name, index=False)
    print('Done')

if __name__ == "__main__":
	main()