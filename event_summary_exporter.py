# Event Summary Exporter
# Patrick Van Zandt, Principal Customer Success Manager
#
# This script uses the /logging/exechistories endpoint in the Airlock Digital REST API to 
# download Execution History events, then uses pandas to summarize the most common values 
# across key fields. Results are written to a multi-sheet Excel workbook.
#
# The core use case for this script is to identify event trends, for example the most common
# parent processes triggering events in Airlock. This can be useful, for example, when you
# are in the implementation phase with devices in Audit Mode and you are looking to identify
# candidates to add as hash approvals, path exclusions, or trusted process exclusions which the
# data shows will have a relatively high impact. This can accelerate the timeline to reaching
# full deployment and later Enforcement Mode because it makes it easy to focus your allowlisting
# analysis and decision-making on the activity patterns that will have the most impact.
#
# This script is published under the GNU General Public License v3.0 and is intended as a working
# example of how to interact with the Airlock API. It is not a commercial product and is provided 
# 'as-is' with no support. No warranty, express or implied, is provided, and the use of this script
# is at your own risk.
#
# This script requires Python 3.x and several common libraries. To install these dependencies, run
#     pip install requests pyyaml pandas pymongo openpyxl
#
# This script reads configuration from a required configuration file named 'airlock.yaml'. Use any text 
# editor to create this file based on the template below, then save in the same folder as this script.
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# The API key must be for a user that is in a Permission Group with the following REST API Role:
#     logging/exechistories
#
# There are several optional configuration parameters which you can include in your airlock.yaml to
# modify the default behavior of this script. Template below showing how to include these. Any 
# optional parameter not included in your airlock.yaml will cause the default to be used
'''
server_name: foo.bar.managedwhitelisting.com    # Required
api_key: yourapikey                             # Required
event_summary_exporter:                         # Required only if including one or more of the below
  lookback_hours: 24                            # Optional - overrides the default (168 hours = 1 week)
  event_types:                                  # Optional - overrides the default (2)
    - 2                                         #   Provide one or more numeric values for event types
    - 3                                         #   (see API documentation for list)
  max_event_quantity: 5000000                   # Optional - overrides the default (10 million)
  top_n_values: 75                              # Optional - overrides the default (100)
  policy_groups:                                # Optional - provide a list of Policy Group names
    - My Workstations Audit Group               #   Provide one or more names of Policy Groups to analyze
    - My Other Workstations Audit Group         #   events from those group(s) only
'''
# This script outputs an Excel file in the same directory that you ran it from. The file name is dynamically
# generated and includes the server name, event quantity, and window of time.
#
# In each worksheet (tab) you will see the events summarized with the top values for a particular field.
# For example, the 'parent_process_name' sheet will contain data like this:
'''
     parent_process_name  |  Count  |  Percentage  |  Unique Hostnames
     --------------------------------------------------------------
     foo.exe              |  9000   |  9.00%       |  500000
     bar.exe              |  7500   |  7.50%       |  125000
     ...                  |  ...    |  ...         |  ...
     process_n            |  500    |  0.50%       |  2 
'''


## Import required libraries ##
import os, re, json, sys
from datetime import datetime, timedelta, timezone
import requests
import yaml
import pandas
from bson.objectid import ObjectId
from openpyxl.utils import get_column_letter


## IMPLEMENT CLI FLAG TO ALLOW DISABLING OF SSL VERIFICATION FOR LAB ENVIRONMENTS ##
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (NOT for production)')
_args, _unknown = parser.parse_known_args()
VERIFY_SSL = not _args.insecure
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #print('WARNING: SSL verification is DISABLED. Your API key and data may be stolen via man-in-the-middle attack.')
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

    event_summary_exporter_config = config.get('event_summary_exporter', {})
    lookback_hours = event_summary_exporter_config.get('lookback_hours', 168) #default is 1 week (24*7=168)
    event_types = event_summary_exporter_config.get('event_types', [2]) #default is Untrusted Execution [Audit] (2)
    max_event_quantity = event_summary_exporter_config.get('max_event_quantity', 10000000) #default is 10 million
    top_n_values = event_summary_exporter_config.get('top_n_values', 100) #default is 100
    policy_groups = event_summary_exporter_config.get('policy_groups', None) #default all Policy Groups
    
    print('\tServer name', f"'{server_name}'")
    print('\tAPI key ending in', f"'{api_key[-4:]}'")
    print('\tLookback hours', f"'{lookback_hours}'")
    print('\tEvent types', event_types)
    print('\tMax event quantity', f"'{max_event_quantity}'")
    print('\tTop n values per field', f"'{top_n_values}'")
    if policy_groups:
        print('\tPolicy groups', policy_groups)

    return server_name, api_key, lookback_hours, event_types, max_event_quantity, top_n_values, policy_groups

# Method that calculates the earliest MongoDB ObjectId (database checkpoint) for some number of hours ago
def objectid_n_hours_ago(n):
    now = datetime.now(timezone.utc)
    n_hours_ago = now - timedelta(hours=n)
    objectid = ObjectId(hex(int(n_hours_ago.timestamp()))[2:] + '0000000000000000')
    print(f"\t\t{objectid} is the minimum checkpoint for events ingested by the server at {n_hours_ago.strftime('%Y-%m-%d %H:%M:%S UTC')} ({n} hours ago)")
    return objectid

# Method to download paginated events (exechistories or svractivities) from Airlock Server
def get_events(event_types, lookback_hours, server_name, api_key, checkpoint, policy_groups=None, max_quantity=10000000):

    # Helper method used to build visual progress bar for console output
    def make_bar(pct, width=20):
        filled = int(round((pct / 100.0) * width))
        return '[' + '#' * filled + '.' * (width - filled) + ']'

    # Define parameters for making requests to server
    request_url = f'https://{server_name}:3129/v1/logging/exechistories'
    request_headers = {'X-ApiKey': api_key}
    request_body = {'checkpoint': checkpoint, 
                    'type': event_types}
    if policy_groups:
        request_body['policy'] = policy_groups
    
    # Define a list to store events as they are downloaded
    events = []

    # Define a counter to keep track of how many batches (pages) of events have been downloaded
    batch_counter = 0

    # Repeat this block of code until a break condition is identified
    while True:
    
        # If maximum event quantity has been reached, exit the while loop
        if len(events) >= max_quantity:
            print('\t\tStopping event download because maximum quantity', max_quantity, 'has been reached')
            break
        
        # Get a batch of events from server and increment batch counter
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
        #print('DEBUG:', request_url, request_headers, request_body, response)
        events_this_batch = response.json()['response']['exechistories']
        batch_counter += 1

        # If no events were returned, exit the while loop
        if not events_this_batch:
            print('\t\tNo events received on most recent request, indicating that the download is complete')
            break
        
        # Add this batch of events to the collected events
        events += events_this_batch

        # Extract checkpoint and ingestion timestamp from last event in this batch
        last_event = events_this_batch[-1]
        last_checkpoint = last_event['checkpoint']  # hex string
        last_ingest_dt_utc = ObjectId(last_checkpoint).generation_time  #ObjectId gen time is UTC
        last_ingest_str_utc = last_ingest_dt_utc.strftime('%Y-%m-%d %H:%M UTC')


        # Compute percent complete from the "oldest known = lookback_hours ago" anchor
        now_utc = datetime.now(timezone.utc)
        age_hours = max(0.0, (now_utc - last_ingest_dt_utc).total_seconds() / 3600.0)
        pct_complete = (lookback_hours - age_hours) / lookback_hours * 100.0
        bar = make_bar(pct_complete)

        # Print progress to console
        if batch_counter == 1:  #print headers 1 time only (on first batch)
            print(f"\t\t{'Request':<11}{'Checkpoint greater than':<28}{'Events returned':<17}{'Latest ingestion timestamp':<28}{'Progress (estimated)':<24}{'Total events':<12}")
        print(f"\t\t{batch_counter:<11}{request_body['checkpoint']:<28}{len(events_this_batch):<17,}{last_ingest_str_utc:<28}{bar:<24}{len(events):<12,}")

        # If less than 10,000 events were returned, exit the while loop
        if len(events_this_batch) < 10000:
            print('\t\tLess than 10K events received on most recent request, indicating that the download is complete')
            break
        
        else:
            request_body['checkpoint'] = last_checkpoint  #increment checkpoint before continuing download

    # Print summary of the event download process
    print('\t\t{:,}'.format(len(events)), 'total events were downloaded')
    
    return events


## MAIN METHOD THAT GETS EXECUTED WHEN THIS SCRIPT IS RUN ##

# Main method to perform Event Summary Export
def main():

    start_time = datetime.now(timezone.utc)
    
    server_name, api_key, lookback_hours, event_types, max_event_quantity, top_n_values, policy_groups = read_config()

    print('\nBeginning data download')

    print('\n\tCalculating database checkpoint to start event downloads from')
    checkpoint = str(objectid_n_hours_ago(lookback_hours))
    
    print('\n\tDownloading Execution History events (depending upon event volume, this may take a while)')
    events = get_events(event_types, lookback_hours, server_name, api_key, checkpoint, policy_groups, max_event_quantity)

    if not events:
        sys.exit(1)

    print('\n\tData download is complete')


    print('\nProcessing data')

    print('\tLoading list of events into a DataFrame')
    events_df = pandas.DataFrame(events)

    print("\tLowercasing Windows paths to assist with aggregation")
    path_columns = ['filename', 'pprocess']
    win_mask = events_df[path_columns].apply(lambda s: s.str.contains(r'[A-Za-z]:\\|\\\\', na=False)).any(axis=1)
    events_df.loc[win_mask, path_columns] = events_df.loc[win_mask, path_columns].apply(lambda s: s.str.lower())

    print('\tGeneralizing usernames to assist with aggregation')
    for col in path_columns:
        events_df[col] = events_df[col].str.replace(r'C:\\users\\[^\\]+', r'C:\\users\\*', regex=True, flags=re.IGNORECASE)
        events_df[col] = events_df[col].str.replace(r'/Users/[^/]+', '/Users/*', regex=True, flags=re.IGNORECASE)

    print('\tRenaming columns for easier readability in output file')
    column_rename_mapping = {
                            'filename': 'filename_full',
                            'pprocess': 'parent_process_full',
                            'sha256': 'file_hash'
                        }
    events_df.rename(columns=column_rename_mapping, inplace=True)
                    
    print("\tSplitting 'filename_full' into 'folder' and 'file' columns")
    events_df[['folder', 'file']] = events_df['filename_full'].str.rpartition('\\').iloc[:, [0, 2]]
    events_df['folder'] = events_df['folder'] + '\\'

    print("\tExtracting 'parent_process_name' column from 'parent_process_full' column")
    events_df['parent_process_name'] = events_df['parent_process_full'].str.rpartition('\\')[2]

    export_columns = ['file_hash', 'folder', 'file', 'filename_full', 'parent_process_name', 'parent_process_full', 'publisher', 'hostname']
    print('\tRemoving unused columns')
    events_df = events_df.loc[:, export_columns]

    print('Done processing data')


    print('\nAnalyzing data')
    results = {}

    # Iterate through each of the defined export columns, performing below steps on each
    counter = 1
    for field in export_columns:

        print(f"\tAnalyzing field {counter}/{len(export_columns)} '{field}' to identify top {top_n_values} values")
        
        # Step 1: Group the dataset by the current field
        # For each unique value of `field`:
        #   - Count = how many total events had this value
        #   - UniqueHostnames = how many distinct hostnames generated those events
        grouped_stats = events_df.groupby(field).agg(
            Count=(field, 'size'),                    # total rows for this value
            UniqueHostnames=('hostname', 'nunique')   # distinct hostnames for this value
        )

        # Step 2: Sort by Count and keep only the top N values
        top_values = grouped_stats.nlargest(top_n_values, 'Count')

        # Step 3: Compute percentage of total events for each of the top values
        total_events = len(events_df)
        percentages = (top_values['Count'] / total_events * 100).round(2)

        # Step 4: Build result rows (convert to list of dicts for export)
        results[field] = [
            {
                field: value,                              # the actual value from this column
                "Count": int(row.Count),                   # how many events had this value
                "Percentage": float(percent),              # % of all events this represents
                "Unique Hostnames": int(row.UniqueHostnames) # how many distinct hosts saw it
            }
            for (value, row), percent in zip(top_values.iterrows(), percentages)
        ]
        counter += 1

    print('Done analyzing data')


    ## WRITE THE RESULTS TO DISK ##

    print('\nExporting data')

    # Calculate export filename
    print('\tCalculating workbook name (file name)')

    server_alias = server_name.split('.')[0].lower()
    first_event_timestamp_str = ObjectId(events[0]['checkpoint']).generation_time.strftime('%Y-%m-%d_%H-%M_utc')
    last_event_timestamp_str = ObjectId(events[-1]['checkpoint']).generation_time.strftime('%Y-%m-%d_%H-%M_utc')
    event_quantity_str = str(len(events))
    
    output_filename = server_alias
    output_filename += '_airlock_event_summary_'
    output_filename += first_event_timestamp_str
    output_filename += '_to_'
    output_filename += last_event_timestamp_str
    output_filename += '_'
    output_filename += event_quantity_str
    output_filename += '.xlsx'

    print(f"\t\tWorkbook name will be '{output_filename}'")

    # Export Data to Excel format
    print('\tWriting output data to disk')
    with pandas.ExcelWriter(output_filename, engine='openpyxl') as writer:

        # Iterate through each of the columns (fields)
        for sheet_name, data in results.items():
            sheet_df = pandas.DataFrame(data)
            
            # Write data
            print(f"\t\tWriting sheet '{sheet_name}'")
            sheet_df.to_excel(writer, sheet_name=sheet_name, index=False)
            
            # Adjust column widths
            worksheet = writer.sheets[sheet_name]
            print('\t\t\tApplying auto-fit to column widths')
            for col_idx, col_name in enumerate(sheet_df.columns, 1):
                max_length = max(sheet_df[col_name].astype(str).map(len).max(), len(col_name)) + 2
                column_letter = get_column_letter(col_idx)
                worksheet.column_dimensions[column_letter].width = max_length
                if col_name == "Percentage":
                    for cell in worksheet[column_letter]:
                        if isinstance(cell.value, (int, float)):
                            cell.number_format = '0.00%'
                            cell.value = cell.value / 100

    print('Done exporting data')

    # Calculate and print metrics on runtime and volume of data processed
    print('\nCalculating runtime and other metrics')
    end_time = datetime.now(timezone.utc)
    total_runtime = end_time - start_time
    total_seconds = total_runtime.total_seconds()
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formatted_time = f'{int(hours):02}:{int(minutes):02}:{int(seconds):02}'
    print(f'\tTotal runtime was {formatted_time} to process')
    print(f'\t\t{lookback_hours} hours of events (quantity: {"{:,}".format(len(events))})')
    print(f'\t\t{top_n_values} top values in each of')
    print(f'\t\t{len(export_columns)} fields')

    print('\nDone! Open the Excel file to view and analyze results.')


# When this .py file is run directly, invoke the main method defined above
if __name__ == '__main__':
    main()