# event_summary_exporter.py
# Version: 1.0
# Last updated: 2024-10-27
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# This is an example of how to bulk export Airlock Execution History (event) data
# and analyze it using the Pandas Data Analysis Library for Python, specifically to
# identify and report on the most common activity patterns. The results can be useful
# for undersanding large data sets, especially when focused on simulated blocks
# ("Untrusted Execution [Audit]") events during initial deployment while you are
# running Airlock in Audit Mode and identifying candidates to consider adding to
# your allowlist in the interest of reducing overall event volume and preparing to
# move to Enforcement Mode.
#
# This script requires an API key for a user in a group with the following API role
# permissions:
#     logging/exechistories
#
# This script ingests configuration from a YAML file. For details on the required
# and optional fields and syntax, reference the documentation in
# event_summary_exporter.md

import requests, json, urllib3, yaml, re, os, pandas as pd
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from openpyxl.utils import get_column_letter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from YAML
config_file_path = 'airlock.yaml'
print('Reading configuration from', config_file_path)
with open(config_file_path, 'r') as file:
    config = yaml.safe_load(file)

# Extract configuration values
print('Processing configuration')
api_key = config['api_key']
server_name = config['server_name']
print(' ', 'server_name:', server_name)
lookback_hours = config['event_summary_exporter'].get('lookback_hours', 168) #default is 1 week (24*7=168)
print(' ', 'lookback_hours:', lookback_hours)
event_types = config['event_summary_exporter'].get('event_types', [2]) #default is Untrusted Execution [Audit] (2)
print(' ', 'event_types:', event_types)
max_event_quantity = config['event_summary_exporter'].get('max_event_quantity', 10000000) #default is 10M
print(' ', 'max_event_quantity:', max_event_quantity)
top_n_values = config['event_summary_exporter'].get('top_n_values', 25) #default is 25
print(' ', 'top_n_values:', top_n_values)
policy_groups = config['event_summary_exporter'].get('policy_groups', []) #default is no filter (all Policy Groups)
print(' ', 'policy_groups:', policy_groups)

# Calculate database checkpoint and human-readable strings regarding window of time to gather events for
end_time = datetime.now(timezone.utc)
end_time_str = end_time.strftime('%Y-%m-%d_%H-%M_UTC')
print('Current time is', end_time_str)
start_time = end_time - timedelta(hours=lookback_hours)
start_time_str = start_time.strftime('%Y-%m-%d_%H-%M_UTC')
print('Start time is', start_time_str)
print('Calculating checkpoint representing', start_time_str, f"({lookback_hours} hours ago)")
checkpoint = str(ObjectId.from_datetime(start_time))
print(checkpoint)

# Download events from the Airlock Server
print(f"Downloading up to {max_event_quantity:,} events from Airlock Server of type(s) {event_types} in time range {start_time_str} to {end_time_str}")
request_url = 'https://' + server_name + ':3129/v1/logging/exechistories'
request_headers = {'X-ApiKey': api_key}
request_body = {'type': event_types, 'policy': policy_groups, 'checkpoint': checkpoint}
events = []
while len(events) < max_event_quantity:
    response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
    exechistories = response.json()['response']['exechistories']
    print(request_url, 'checkpoint >', request_body['checkpoint'], 'returned', len(exechistories), 'records')
    events += exechistories
    if len(exechistories) < 10000:
        break  
    request_body['checkpoint'] = exechistories[len(exechistories)-1]['checkpoint']
print('Downloaded', '{:,}'.format(len(events)), 'events')
   
# Load events into a dataframe
print('Loading events into a Pandas DataFrame')
events_df = pd.DataFrame(events)

#Generalize usernames
print('Replacing usernames with asterisks')
for column in ['filename', 'pprocess']:
    events_df[column] = events_df[column].str.replace(r'C:\\users\\[^\\]+', r'C:\\users\\*', regex=True, flags=re.IGNORECASE)
    events_df[column] = events_df[column].str.replace('/Users/[^/]+', '/Users/*', regex=True, flags=re.IGNORECASE)   

# Rename columns
column_rename_mapping = {
                        'filename': 'filename_full',
                        'pprocess': 'parent_process_full',
                        'sha256': 'file_hash'
                       }
print('Renaming columns')
for key in column_rename_mapping.keys():
    print(' ', key, '-->', column_rename_mapping[key])
events_df.rename(columns=column_rename_mapping, inplace=True)
                   
# Split 'filename_full' column into 'folder' and 'file' columns
print('Splitting filename_full column into folder and file columns')
events_df[['folder', 'file']] = events_df['filename_full'].str.rpartition('\\').iloc[:, [0, 2]]
events_df['folder'] = events_df['folder'] + '\\'

# Split 'parent_process_full' column to create 'parent_process_name'
print('Extracting parent_process_name from parent_process_full')
events_df['parent_process_name'] = events_df['parent_process_full'].str.rpartition('\\')[2]

# Define list of columns to keep (also used to determine sheet order in exported Excel file)
export_columns = ['file_hash', 'folder', 'file', 'filename_full', 'parent_process_name', 'parent_process_full', 'publisher', 'hostname']
print('Dropping all columns except', export_columns)
events_df = events_df.loc[:, export_columns]

# Calculate results for each field
results = {}
print('Analyzing events to find top', top_n_values, 'most common values for each remaining column')
for field in export_columns:
    print(' ', field, end=' ')
    counts = events_df[field].value_counts().head(top_n_values)
    total = len(events_df)
    percentages = (counts / total * 100).round(2)
    results[field] = [
        {field: value, "Count": count, "Percentage": percent}
        for value, count, percent in zip(counts.index, counts, percentages)
        ]
    print('[Done]')
print('Data collection and analysis is complete')

# Write results to disk
print('Beginning export of results')
output_file_name = server_name.split(".")[0] + '_event_summary_' + start_time_str + '_to_' + end_time_str + '_' + str(len(events)) + '.xlsx'
print('Data will be written to', output_file_name)
with pd.ExcelWriter(output_file_name, engine='openpyxl') as writer:
    for sheet_name, data in results.items():
        sheet_df = pd.DataFrame(data)
        sheet_df.to_excel(writer, sheet_name=sheet_name, index=False)
        worksheet = writer.sheets[sheet_name]
        for col_idx, col_name in enumerate(sheet_df.columns, 1):
            max_length = max(sheet_df[col_name].astype(str).map(len).max(), len(col_name)) + 2
            column_letter = get_column_letter(col_idx)
            worksheet.column_dimensions[column_letter].width = max_length
            if col_name == "Percentage":
                for cell in worksheet[column_letter]:
                    if isinstance(cell.value, (int, float)):
                        cell.number_format = '0.00%'
                        cell.value = cell.value / 100
print('Export is done')