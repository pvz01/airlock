# Example of how to produce a custom report on installed agents, in this example
# looking for all agents which have been offline for more than 7 days and writing
# the results to a CSV file.

# Import required libraries
import requests
import json
import datetime
import dateutil
import csv

# Get list of all offline agents
url = 'https://SERVER-NAME:3129/v1/agent/find'
headers = {'X-APIKey': 'API-KEY'}
payload = {'status': 0}  # 0=offline 1=online 3=safemode
response = requests.post(url, json=payload, headers=headers, verify=False)
offline_agent_list = response.json()['response']['agents']

# Calculate number of days offline for each agent in the list
now = datetime.datetime.now(datetime.timezone.utc)
for agent in offline_agent_list:
    lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
    agent['daysoffline'] = (now - lastcheckin).days

# Build a filtered list of just those agents offline for more than 7 days
offline_more_than_seven_days = []
for agent in offline_agent_list:
    if agent['daysoffline'] > 7:
        offline_more_than_seven_days.append(agent)
    
# Write the data to a CSV file
csv_file_name = 'airlock_agents_offline_more_than_7_days.csv'
with open(csv_file_name, mode='w', newline='') as csv_file:
    fieldnames = offline_more_than_seven_days[0].keys()
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(offline_more_than_seven_days)
print(len(offline_more_than_seven_days), 'records written to', csv_file_name)