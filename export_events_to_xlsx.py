# export_events_to_xlsx.py
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# This script is published under the GNU General Public License v3.0 and is intended as a working example 
# of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
# support. No warranty, express or implied, is provided, and the use of this script is at your own risk.
#
# To install dependencies, run this command:
#     pip install requests urllib3 pyyaml pandas pymongo openpyxl

# Import required libraries
import requests, json, urllib3, datetime, yaml, pandas, sys, os
from datetime import datetime, timedelta, timezone
from bson import ObjectId

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Method that reads configuration from a YAML file on disk
def read_config(config_file_name='airlock.yaml'):
    if not os.path.exists(config_file_name):
        print('ERROR: The configuration file', config_file_name, 'does not exist.')
        sys.exit(1)
    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', config_file_name, 'for server', config['server_name'], 'and event types', config['event_types'])
    return config

# Method that calculates the earliest MongoDB ObjectId (database checkpoint) for some number of hours ago
def objectid_n_hours_ago(n):
    datetime_n_hours_ago = datetime.now(timezone.utc) - timedelta(hours=n)
    print('Calculating earliest objectid for documents ingested', n, 'hours ago:', datetime_n_hours_ago)
    timestamp = int(datetime_n_hours_ago.timestamp())
    objectid = ObjectId(hex(timestamp)[2:] + '0000000000000000')
    print('Result:', objectid)
    return objectid

# Method that downloads events from the Airlcok Server
def get_events(config):

    #define a list to store the downloaded events
    collected_events = []
    
    #define static configuration used for all requests to server
    request_url = 'https://' + config['server_name'] + ':3129/v1/logging/exechistories'
    request_headers = {'X-ApiKey': config['api_key']}
    request_body = {'type': config['event_types']}

    #OPTIONAL: uncomment do use server side filtering on Policy Group(s)
    #request_body['policy'] = ['Policy Group Name 1', 'Policy Group Name 2']

    #loop until break statement
    while True:

        #get next page of events from server starting with current checkpoint
        request_body['checkpoint'] = config['checkpoint']
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
        events = response.json()['response']['exechistories']
        if events is None:
            events = []
        print(request_url, 'checkpoint >', request_body['checkpoint'], 'returned', len(events), 'records')

        #check if any events were returned
        if len(events) > 0:

            #increment checkpoint using value from last event returned in this page
            config['checkpoint'] = events[len(events)-1]['checkpoint']
            print('Checkpoint on last event: ', config['checkpoint'])

            #append new events to list of collected events
            collected_events += events
            
            #check if this page was <10K events, if yes this means this is the last page
            if len(events) < 10000:
                break
        
        #if no events were returned, we already have all the events
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

If you are interested in events for only a subset of your Policy Groups, it is recommended to use
server-side filtering. Reference the commented out example in the get_events() method to accomplish
this.

This script makes no changes. It is a data extract tool only.

This script reads server configuration from a configuration file named airlock.yaml. Use any text editor
to create this file based on the template below, then save in the same folder as this Python script.

server_name: foo.bar.managedwhitelisting.com
api_key: your-api-key
event_types:  # Define a list of 1 or more event types to download
#  - 0  #Trusted Execution
#  - 1  #Blocked Execution
  - 2  #Untrusted Execution [Audit]
#  - 3  #Untrusted Execution [OTP]
#  - 4  #Trusted Path Execution
#  - 5  #Trusted Publisher Execution
#  - 6  #Blocklist Execution
#  - 7  #Blocklist Execution [Audit]
#  - 8  #Trusted Process Execution

The API key provided in the YAML must have permission to the following API endpoint(s):
	logging/exechistories

This script is published under the GNU General Public License v3.0 and is intended as a working example 
of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

	"""
    print(readme_message)

    # Get configuration
    config = read_config()

    # Ask how far back to look at events
    days = int(input("\nEnter the number of days to export, looking back from today's date (e.g., entering '7' will export events from the last week): "))
    hours = 24 * days

    # Calculate a MongoDB ObjectId base on lookback period, set this as initial checkpoint
    objectid = objectid_n_hours_ago(hours)
    config['checkpoint'] = str(objectid)
    
    # Download the events
    print('\nGetting events from server')
    events = get_events(config)

    # Load the events into a DataFrame
    print('\nLoading events into a DataFrame')
    events_df = pandas.DataFrame(events)
    print(len(events_df), 'rows are in DataFrame')

    # Manipulate the events in the DataFrame before exporting them
    #
    # OPTIONAL: Add or adjust client side filtering or sorting here. Examples below.
    #
    # Example 1: filter on file name ends with .exe
    # print('Removing all except .exe files')
    # events_df = events_df[events_df['filename'].str.lower().str.endswith('.exe')]
    # print(len(events_df), 'rows are in DataFrame')
    #
    # Example 2: de-duplicate based on sha256, keeping only the first occurrence of each hash
    # print('De-duplicating based on file hash (sha256)')
    # events_df = events_df.drop_duplicates(subset='sha256', keep='first')
    # print(len(events_df), 'rows are in DataFrame')
    #
    # Example 3: filter to exclude signed files
    # print('Removing events for signed files, leaving only unsigned files remaining')
    # events_df = events_df[events_df['publisher'] == 'Not Signed']
    # print(len(events_df), 'rows are in DataFrame')

    print('\nExporting events from DataFrame to disk')    

    # Calculate file name for export
    server_alias = config['server_name'].split('.')[0]
    timestamp = datetime.today().strftime('%Y-%m-%d_%H.%M')
    file_name = 'airlock_events_' + server_alias + '_' + timestamp + '_last_' + str(days) + '_days.xlsx'
    print('Data will be written to', file_name)

    # Write data to disk
    events_df.to_excel(file_name, index=False)
    print('\nDone!')

if __name__ == "__main__":
	main()