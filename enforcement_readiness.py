# Enforcement Readiness Assessment
# Patrick Van Zandt, Principal Customer Success Manager
#
# This script downloads three key pieces of data for the Policy Group that you select
# 1. All simulated block events (events with type Untrusted Execution [Audit]) for the last 30 days
# 2. All server activity history events for the last 30 days
# 3. The list of agents including their hostname and last checkin time
#
# It then summarizes and combines the data, providing an easy-to-read spreadsheet format output which has
# key metrics to enable you to assess risk on a per-device (hostname) basis of moving devices from Audit
# Mode to Enforcement Mode.
# 
# As an example, if you were to apply these filters to the output file in Excel, Sheets, or equivalent
#    Days since agent was installed:  > 30
#    Days since last check-in:  < 7
#    Simulated blocks (last 30 days):  0
# then you will have a list of hostnames that were installed 30+ days ago, have checked in within the last
# week, and have generated 0 Untrusted Execution [Audit] events in the last 30 days. Based on the data, 
# these devices are very low risk to move to Enforcement Mode.
#
# This script is published under the GNU General Public License v3.0 and is intended as a working example 
# of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
# support. No warranty, express or implied, is provided, and the use of this script is at your own risk.
#
# This script requires Python 3.x and several common libraries. To install these dependencies, run
#     pip install requests pyyaml pandas python-dateutil pymongo openpyxl xlsxwriter
#
# This script reads configuration from a required configuration file named airlock.yaml. Use any text editor
# to create this file based on the template below, then save in the same folder as this Python script.
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# The API key must be for a user that is in a Permission Group with the following REST API Roles:
#     group
#     group/policies
#     group/agents
#     logging/exechistories
#     logging/svractivities
#
# There are also several optional configuration parameters which you can include in your airlock.yaml to
# modify the default behavior of this script. Template below showing how to include these.
'''
server_name: foo.bar.managedwhitelisting.com    # Required
api_key: yourapikey                             # Required
enforcement_readiness:                          # Required only if including one or more of the below
    lookback_days: 45                           # Optional - overrides the default (30 days)
    policy_group_name:                          # Optional - skips selection prompt if match is found
'''

## IMPORT REQUIRED LIBRARIES ##
import requests
import json
import yaml
import pandas
import dateutil.parser
import os
import sys
from datetime import datetime, timedelta, timezone
from bson import ObjectId


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

    enforcement_readiness_config = config.get('enforcement_readiness', {})
    lookback_days = int(enforcement_readiness_config.get('lookback_days', 30)) # default 30 if not provided
    policy_group_name = enforcement_readiness_config.get('policy_group_name', None)

    print('\tServer name', f"'{server_name}'")
    print('\tAPI key ending in', f"'{api_key[-4:]}'")
    print('\tLookback days', f"'{lookback_days}'")
    if policy_group_name:
        print('\tPreselected policy group', f"'{policy_group_name}'")

    return server_name, api_key, lookback_days, policy_group_name

# Method that calculates the earliest MongoDB ObjectId (database checkpoint) for some number of days ago
def objectid_n_days_ago(n):
    now = datetime.now(timezone.utc)
    n_days_ago = now - timedelta(days=n)
    n_days_ago_string = n_days_ago.strftime('%Y-%m-%d %H:%M:%S UTC')
    objectid = ObjectId(hex(int(n_days_ago.timestamp()))[2:] + '0000000000000000')
    print(f"\t\t{objectid} is the minimum checkpoint for events ingested by the server at {n_days_ago_string} ({n} days ago)")
    return objectid

# Method that gets the list of Policy Groups from the server
def get_groups(server_name, api_key):
    request_url = 'https://' + server_name + ':3129/v1/group'
    request_headers = {'X-ApiKey': api_key}
    response = requests.post(request_url, headers=request_headers, verify=VERIFY_SSL)
    return response.json()['response']['groups']

# Method that iterates through a list of Policy Groups, interrogates policy of each, and adds the auditmode field to the list
def add_audit_mode_to_group_list(groups, server_name, api_key):
    counter = 1
    for group in groups:
        print(f"\tAnalyzing Policy Group {counter} of {len(groups)}: '{group['name']}'")
        request_url = 'https://' + server_name + ':3129/v1/group/policies'
        request_headers = {'X-ApiKey': api_key}
        request_body = {'groupid': group['groupid']}
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
        auditmode = int(response.json()['response']['auditmode'])
        if auditmode == 1:
            group['auditmode'] = True
            print('\t\tAudit Mode')
        else:
            group['auditmode'] = False
            print('\t\tEnforcement Mode')
        counter += 1
    return groups

# Method that filters a list of policy groups based on the auditmode field
def filter_group_list(groups, auditmode=True):
    return [group for group in groups if group['auditmode'] == auditmode]

# Method to select from a list of Policy Groups by prompting the user
def choose_group(groups, prompt_message, server_name):
    for index, item in enumerate(groups):
        print(f"\t\t{index+1}  '{item['name']}'")
    index = int(input(prompt_message)) - 1
    return groups[index]

# Method to download the list of agents in a Policy Group
def get_agents_in_group(group, server_name, api_key):
    request_url = 'https://' + server_name + ':3129/v1/group/agents'
    request_headers = {'X-ApiKey': api_key}
    request_body = {'groupid': group['groupid']}
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
    return response.json()['response']['agents']

# Method to add untrusted execution counts to a list of agents
def add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts):
    for agent in agents:
        agent['untrusted_30d'] = last_30_days_counts.get(agent['hostname'], 0)
        agent['untrusted_15d'] = last_15_days_counts.get(agent['hostname'], 0)
        agent['untrusted_7d'] = last_7_days_counts.get(agent['hostname'], 0)
    return agents

# Method to add the number of days since last check-in to a list of agents by comparing lastcheckin to current datetime
def add_checkin_age(agents):
    now = datetime.now(timezone.utc)
    for agent in agents:
        lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
        agent['checkin_age'] = (now - lastcheckin).days
    return agents

# Method to download paginated events (exechistories or svractivities) from Airlock Server
def get_events(event_type, lookback_days, server_name, api_key, checkpoint, group_name=None, max_quantity=10000000):

    # Helper method used to build visual progress bar for console output
    def make_bar(pct, width=20):
        filled = int(round((pct / 100.0) * width))
        return '[' + '#' * filled + '.' * (width - filled) + ']'

    # Define parameters for making requests to server
    request_url = f'https://{server_name}:3129/v1/logging/{event_type}'
    request_headers = {'X-ApiKey': api_key}
    request_body = {'checkpoint': checkpoint}
    if event_type == 'exechistories':
        request_body['policy'] = [group_name]
        request_body['type'] = [2]  # Untrusted Execution [Audit]
    
    # Define a list to store events as they are downloaded
    events = []

    # Define a counter to keep track of how many batches (pages) of events have been downloaded
    batch_counter = 0

    # Repeat this block of code until a break condition is identified
    while True:
    
        # If maximum event quantity has been reached, exit the while loop
        if len(events) >= max_quantity:
            print('\t\tStopping event download because maximum quantity', max_quantity, 'has been reached')
            sys.exit(1)
        
        # Get a batch of events from server and increment batch counter
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=VERIFY_SSL)
        events_this_batch = response.json()['response'][event_type]
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

        # Compute percent complete from the "oldest known = lookback_days ago" anchor
        now_utc = datetime.now(timezone.utc)
        age_days = max(0.0, (now_utc - last_ingest_dt_utc).total_seconds() / 86400.0)
        pct_complete = (lookback_days - age_days) / lookback_days * 100.0
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
    print('\t\t{:,}'.format(len(events)), 'total', event_type, 'events were downloaded')
    
    return events

# Method to count the number of events by hostname within different timeframes
def count_events_by_hostname_with_timeframes(events):
    last_30_days_counts = {}
    last_15_days_counts = {}
    last_7_days_counts = {}

    current_time = datetime.now(timezone.utc)
    last_30_days_threshold = current_time - timedelta(days=30)
    last_15_days_threshold = current_time - timedelta(days=15)
    last_7_days_threshold = current_time - timedelta(days=7)

    for event in events:
        hostname = event.get('hostname')
        event_time = datetime.strptime(event.get('datetime'), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

        if event_time >= last_30_days_threshold:
            last_30_days_counts[hostname] = last_30_days_counts.get(hostname, 0) + 1

        if event_time >= last_15_days_threshold:
            last_15_days_counts[hostname] = last_15_days_counts.get(hostname, 0) + 1

        if event_time >= last_7_days_threshold:
            last_7_days_counts[hostname] = last_7_days_counts.get(hostname, 0) + 1

    return last_30_days_counts, last_15_days_counts, last_7_days_counts

# Method to process the SAH logs extract the most recent registration timestamp per hostname
def get_last_registrations_per_hostname(server_activity_logs):
    results = {}
    for entry in server_activity_logs:
        if entry['task'] == 'Client Operation' and entry['user'] == 'SYSTEM':
            if entry['description'].startswith('New agent'):
                hostname = entry['description'].split()[2].lower()  # hostname is 3rd word in the description field
                timestamp = dateutil.parser.parse(entry['datetime'])
                if hostname not in results or timestamp > results[hostname]:
                    results[hostname] = timestamp
    return results

# Method to add the number of days since installation to each agent
def add_install_age(agents, registration_timestamps, max_days):
    now = datetime.now(timezone.utc)
    for agent in agents:
        registration_timestamp = registration_timestamps.get(agent['hostname'].lower())
        if registration_timestamp is None: 
            agent['install_age'] = f'> {max_days}'
        else:
            agent['install_age'] = (now - registration_timestamp).days
    return agents

# Method to collect agents, execution history events, and server activity logs
def collect_data(server_name, api_key, group, days):
    start_time = datetime.now(timezone.utc)
    print('\nBeginning data download')

    print('\tDownloading agents in policy group', f"'{group['name']}'")
    agents = get_agents_in_group(group, server_name, api_key)
    if not agents:
        print('\t\tNo Enforcement Agents are in the group you selected')
        sys.exit(1)
    print("\t\t{:,}".format(len(agents)), 'agents downloaded')

    print('\n\tCalculating database checkpoint to start event downloads from')
    checkpoint = str(objectid_n_days_ago(days))

    print('\n\tDownloading Execution History events (depending upon event volume, this may take a while)')
    events = get_events('exechistories', days, server_name, api_key, checkpoint, group['name'])

    print('\n\tDownloading Server Activity History events (depending upon event volume, this may take a while)')
    sah_logs = get_events('svractivities', days, server_name, api_key, checkpoint)

    print('\n\tData download is complete')

    return agents, events, sah_logs, start_time


## MAIN METHOD THAT GETS EXECUTED WHEN THIS SCRIPT IS RUN ##

# Main method to perform Enforcement Readiness assessment
def main():
    
    server_name, api_key, lookback_days, policy_group_name = read_config()
    
    print('\nDownloading list of groups from server')
    groups = get_groups(server_name, api_key)
    print(f"\t{len(groups)} groups downloaded")

    print('\nReading policy for each group to determine Audit vs Enforcement Mode')
    groups = add_audit_mode_to_group_list(groups, server_name, api_key)

    print('\nFiltering group list to remove Enforcement Mode groups')
    groups = filter_group_list(groups, True)
    print(f"\t{len(groups)} groups remain")

    group = None
    if policy_group_name is not None:
        print('\nIterating through filtered group list to look for a match for preconfigured group name', policy_group_name)
        for possible_group in groups:
            if possible_group['name'] == policy_group_name:
                group = possible_group
                print('Found a match:', group)
                break
        if group is None:
            print('No match found for an Audit Mode group with the preconfigured group name:', policy_group_name)

    if group is None:
        group = choose_group(groups, '\nWhich Policy Group do you want to run Enforcement Readiness analysis on? Enter number and press return: ', server_name)

    agents, events, sah_logs, start_time = collect_data(server_name, api_key, group, lookback_days)

    print('\nAnalyzing data')
    
    print('\tSummarizing Execution History events to get counts by hostname and time intervals')
    last_30_days_counts, last_15_days_counts, last_7_days_counts = count_events_by_hostname_with_timeframes(events)

    print('\tSummarizing Server Activity History events to get most recent registration for each unique hostname')
    registration_timestamps = get_last_registrations_per_hostname(sah_logs)

    print('\tAppending Execution History event counts list of agents')
    agents = add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts)

    print('\tCalculating Checkin Age for each hostname and adding to list of agents')
    agents = add_checkin_age(agents)

    print('\tCalculating Installation Age for each hostname and appending to list of agents')
    agents = add_install_age(agents, registration_timestamps, max_days=lookback_days)

    print('\tLoading list of agents into a DataFrame')
    agents_df = pandas.DataFrame(agents)

    columns_to_remove = ['freespace', 'groupid', 'domain', 'ip', 'status', 'username', 'clientversion', 'policyversion']
    print('\tRemoving unused columns', columns_to_remove)
    agents_df.drop(columns_to_remove, axis=1, inplace=True)

    column_order = ['hostname', 'untrusted_7d', 'untrusted_15d', 'untrusted_30d', 'checkin_age', 'install_age']
    print('\tReordering columns to', column_order)
    agents_df = agents_df[column_order]

    rename_map = {'hostname': 'Device hostname',
                  'untrusted_30d': 'Simulated blocks (last 30 days)',
                  'untrusted_15d': 'Simulated blocks (last 15 days)',
                  'untrusted_7d':  'Simulated blocks (last 7 days)',
                  'checkin_age':   'Days since last check-in',
                  'install_age':   'Days since agent was installed'}
    print('\tRenaming columns to human-friendly names')
    agents_df = agents_df.rename(columns=rename_map)

    print('\nExporting data')

    # Build a safe sheet name for Excel (<=31 chars, no : \ / ? * [ ])
    raw_sheet_name = group['name']
    print(f"\tBuilding an Excel-compatible sheet name for group '{raw_sheet_name}'")
    safe_sheet_name = (raw_sheet_name.translate({ord(c): '_' for c in r':\/?*[]'}))[:31]
    print(f"\t\tSheet name will be '{safe_sheet_name}'")

    # Calculate export filename
    print('\tCalculating workbook name (file name)')
    output_filename = f"{server_name.split('.')[0]}_"
    output_filename += f"{safe_sheet_name.lower().replace(' ', '-')}_"
    output_filename += f"airlock_enforcement_readiness_"
    output_filename += f"{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M_utc')}.xlsx"
    print(f"\t\tWorkbook name will be '{output_filename}'")

    # Export Data to Excel format
    print('\tWriting output data to disk')
    with pandas.ExcelWriter(output_filename, engine='xlsxwriter') as writer:
        agents_df.to_excel(writer, index=False, sheet_name=safe_sheet_name, na_rep='')

        # Adjust column widths on exported Excel file
        print('\t\tApplying auto-fit to column widths')
        worksheet = writer.sheets[safe_sheet_name]
        for col_name in agents_df.columns:
            col_idx = agents_df.columns.get_loc(col_name)
            max_len = max(agents_df[col_name].astype(str).map(len).max(), len(col_name))
            worksheet.set_column(col_idx, col_idx, max_len + 1)
    print('\tDone exporting data')

    # Calculate and print metrics on runtime and volume of data processed
    print('\nCalculating runtime and other metrics')
    end_time = datetime.now(timezone.utc)
    total_runtime = end_time - start_time
    total_seconds = total_runtime.total_seconds()
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formatted_time = f'{int(hours):02}:{int(minutes):02}:{int(seconds):02}'
    print(f'\tTotal runtime was {formatted_time} to process')
    print(f'\t\t{lookback_days} days of events (quantity: {"{:,}".format(len(events))})')
    print(f'\t\t{lookback_days} days of server activity logs (quantity: {"{:,}".format(len(sah_logs))})')
    print(f'\t\t{"{:,}".format(len(agents))} agents')

    print('\nDone! Open the Excel file to view and analyze results, and consider using move_devices.py to transition "quiet" agents to Enforcement Mode.')

# When this .py file is run directly, invoke the main method defined above
if __name__ == '__main__':
    main()