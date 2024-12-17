# Example of how to export Server Activity History Logs to disk in CSV format
# 
# Use this command to install prerequisites:
#	  pip install requests datetime


##CONFIGURATION

config_file_name = 'airlock.yaml'

# Checkpoint
# To export new data, provide checkpoint from the last row of previous export
# To export all data, set to '000000000000000000000000'
checkpoint = '000000000000000000000000'


##RUNTIME

# Import required libraries
import requests
import json
import csv
import datetime
import yaml

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read server config
with open(config_file_name, 'r') as file:
    config = yaml.safe_load(file)

# Get data from server
request_url = f'https://{config['server_name']}:3129/v1/logging/svractivities'
request_headers = {'X-APIKey': config['api_key']}
collected_data = []
while True:
	request_body = {'checkpoint': checkpoint}
	print('Querying server for entries after checkpoint', checkpoint)
	response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
	svractivities = response.json()['response']['svractivities']
	checkpoint = svractivities[len(svractivities)-1]['checkpoint']
	print('Found', len(svractivities), 'rows of data, the last of which has checkpoint', checkpoint) 
	collected_data += svractivities
	if len(svractivities) < 10000:
		# We have all the data. Exit the while loop.
		break
print(len(collected_data), 'total rows of data downloaded from server')

# Calculate file name for export
server_alias = config['server_name'].replace(".", "-")
timestamp = datetime.datetime.today().strftime("%Y-%m-%d_%H.%M")
file_name = f'airlock_server_activity_{server_alias}_{timestamp}.csv'

# Write data to disk
print('Beginning export of data to', file_name)
with open(file_name, mode='w', newline='') as csv_file:
	fieldnames = collected_data[0].keys()
	writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
	writer.writeheader()
	writer.writerows(collected_data)
print(len(collected_data), 'records written to', file_name)
