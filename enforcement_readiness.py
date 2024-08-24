# enforcement_readiness.py
# Version: 2.0
# Last updated: 2024-08-24
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to generate MS Excel format report on recent untrusted executions
# which can be used to determine readiness to promote agents to enforcement mode
# on a per-hostname basis (for example by using move_agents.py).
#
# Known limitation:
# If you have duplicate hostnames in your environment, the sum of events for all 
# agents with the same hostname will be returned for all agents with that hostname.

import requests, json, urllib3, datetime, time, yaml, pandas, bson, dateutil.parser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(file_name):
	with open(file_name, 'r') as file:
		config = yaml.safe_load(file)
	print('Read config from', file_name, 'for server', config['server_name'])
	return config

def objectid_n_days_ago(n):
	datetime_n_days_ago = datetime.datetime.now() - datetime.timedelta(days=n)
	print('Calculating database checkpoint for', datetime_n_days_ago)
	timestamp = int(datetime_n_days_ago.timestamp())
	objectid_hex = hex(timestamp)[2:] + '0000000000000000'
	return bson.ObjectId(objectid_hex)

def get_groups(server_name, api_key):
	request_url = 'https://' + server_name + ':3129/v1/group'
	request_headers = {'X-APIKey': api_key}
	response = requests.post(request_url, headers=request_headers, verify=False)
	return response.json()['response']['groups']

def add_audit_mode_to_group_list(groups, server_name, api_key):
	counter = 1
	for group in groups:
		print('Analyzing group', counter, 'of', len(groups), group['name'], end=' ')
		request_url = 'https://' + server_name + ':3129/v1/group/policies'
		request_headers = {'X-APIKey': api_key}
		request_body = {'groupid': group['groupid']}
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		auditmode = int(response.json()['response']['auditmode'])
		if auditmode == 1:
			group['auditmode'] = True
			print('[Audit]')
		else:
			group['auditmode'] = False
			print('[Enforcement]')
		counter += 1
	return groups

def filter_group_list(groups, auditmode):
	filtered_groups = []
	for group in groups:
		if group['auditmode'] == auditmode:
			filtered_groups.append(group)
	return filtered_groups

def choose_group(groups, prompt_message, server_name):
	print('These are the Audit Mode groups on', server_name)
	for index, item in enumerate(groups):
		print(index+1, '\t', item['name'])
	index = int(input(prompt_message))-1
	return groups[index]

def get_agents_in_group(group, server_name, api_key):
	request_url = 'https://' + server_name + ':3129/v1/group/agents'
	request_headers = {'X-APIKey': api_key}
	request_body = {'groupid': group['groupid']}
	response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
	return response.json()['response']['agents']

def add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts):
	for agent in agents:
		agent['untrusted_executions_last_30_days'] = last_30_days_counts.get(agent['hostname'], 0)
		agent['untrusted_executions_last_15_days'] = last_15_days_counts.get(agent['hostname'], 0)
		agent['untrusted_executions_last_7_days'] = last_7_days_counts.get(agent['hostname'], 0)
	return agents

def add_lastcheckin_days_ago(agents):
	now = datetime.datetime.now(datetime.timezone.utc)
	for agent in agents:
		lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
		agent['lastcheckin_days_ago'] = (now - lastcheckin).days
	return agents

def move_df_column_to_position(df, column_name, new_position):
	column_to_move = df.pop(column_name)
	df.insert(new_position, column_name, column_to_move)
	return df
	
def get_exechistories_for_group(group, server_name, api_key, types=[2], checkpoint='000000000000000000000000'):
	request_url = 'https://' + server_name + ':3129/v1/logging/exechistories'
	request_headers = {'X-APIKey': api_key}
	request_body = {'type': types, #the default [2] denotes "Untrusted Execution [Audit]"
					'checkpoint': checkpoint,
					'policy': [group['name']]}
	
	collected_events = []
	while True:

		#get up to 10K events from server
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		events = response.json()['response']['exechistories']
		print(request_url, request_body, 'returned', len(events), 'events')

		#append new events to list of collected events
		collected_events += events
		
		#if we got exactly 10K events back, reset checkpoint based on last event returned to use for next iteration
		if len(events) == 10000:
			request_body['checkpoint'] = events[len(events)-1]['checkpoint']

		#any other quantity except 10K means we already have all the events so we can exit the while loop
		else:
			break
	
	return collected_events

def count_events_by_hostname_with_timeframes(events):
	# Initialize the dictionaries for all events, last 15 days, and last 7 days
	last_30_days_counts = {}
	last_15_days_counts = {}
	last_7_days_counts = {}

	# Get the current date and time
	current_time = datetime.datetime.utcnow()

	# Calculate the time thresholds
	last_30_days_threshold = current_time - datetime.timedelta(days=30)
	last_15_days_threshold = current_time - datetime.timedelta(days=15)
	last_7_days_threshold = current_time - datetime.timedelta(days=7)

	for event in events:
		hostname = event.get('hostname')
		event_time = datetime.datetime.strptime(event.get('datetime'), '%Y-%m-%dT%H:%M:%SZ')
		
		# Count for events in the last 30 days
		if event_time >= last_30_days_threshold:
			if hostname in last_30_days_counts:
				last_30_days_counts[hostname] += 1
			else:
				last_30_days_counts[hostname] = 1
		
		# Count for events in the last 15 days
		if event_time >= last_15_days_threshold:
			if hostname in last_15_days_counts:
				last_15_days_counts[hostname] += 1
			else:
				last_15_days_counts[hostname] = 1

		# Count for events in the last 7 days
		if event_time >= last_7_days_threshold:
			if hostname in last_7_days_counts:
				last_7_days_counts[hostname] += 1
			else:
				last_7_days_counts[hostname] = 1
	
	return last_30_days_counts, last_15_days_counts, last_7_days_counts



def main():
	
	readme_message = """
Welcome to the PVZ's Airlock Enforcement Readiness Assessment tool. This tool is an example of how to
generate an Excel-readable spreadsheet with key data points to assist with assessing which computers
in your environment are relatively low versus relatively high to promote from Audit Mode to Enforcement
Mode. To accomplish this, it exports all events in the last 30 days from your chosen Audit Mode policy,
summarizes them by hostname, and then exports this along with a list of hostnames in that policy. It
also adds a column which indicates how many days ago each agent last connected to the server. 

This script makes no changes to your environment and makes no specific recommendation on what to move
to enforcement. Instead, it equips you to do "what if" scenarios in Excel, for example if you were to
filter the results on 
  lastcheckin_days_ago < 3
  -and-
  untrusted_executions_last_15_days < 5
you would be left with a list of devices which have had minimal events in the last 2+ weeks and that
have also connected recently enough that you know you have relatively complete data. Many customers
consider that devices matching this criteria are quite low risk to move to Enforcement Mode and use
same or similar criteria to promote devices.

This tool reads server configuration from a YAML configuration file. Use a text editor of your choice 
to create a configuration file matching the syntax below and place it in the same folder as the PY
script.

server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey

The API key provided in the YAML have permission to the following API endpoints:
	group
	group/policies
	group/agents
	logging/exechistories

This script is published under the GNU General Public License v3.0 and is intended as a working example 
of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

	"""

	print(readme_message)
	
	#get config from YAML on disk
	config_file_name = input('Enter the name of a YAML file containing server configuration: ')
	config = read_config(config_file_name)
	server_name = config['server_name']
	api_key = config['api_key']

	print('Getting list of groups from server')
	groups = get_groups(server_name, api_key)

	print('Reading policy for each group to determine Audit vs Enforcement Mode')
	groups = add_audit_mode_to_group_list(groups, server_name, api_key)

	print('Filtering group list to include Audit Mode groups only')
	groups = filter_group_list(groups, True)

	group = choose_group(groups, 'Which group do you want to perform analysis on? Enter number and press return: ', server_name)

	start_time = time.time()
	print(datetime.datetime.fromtimestamp(start_time).strftime('%H:%M:%S'), 'Beginning data collection')

	print('Getting list of agents in', group['name'])
	agents = get_agents_in_group(group, server_name, api_key)
	print('Downloaded list of', len(agents), 'agents')
   
	#calculate timestamps and associated checkpoint (objectid)  
	days = 30
	now = datetime.datetime.utcnow()
	timestamp_to_str = now.strftime('%Y-%m-%d_%H-%M_UTC')
	datetime_from = now - datetime.timedelta(days=days)
	timestamp_from_str = datetime_from.strftime('%Y-%m-%d_%H-%M_UTC')
	checkpoint = str(objectid_n_days_ago(days))
	
	print('Downloading events ranging from', timestamp_from_str, 'to', timestamp_to_str, 'for group', group['name'])
	events = get_exechistories_for_group(group, server_name, api_key, checkpoint=checkpoint)
	print('Downloaded', len(events), 'events')

	print('Data collection is complete, beginning analysis')

	print('Summarizing events by hostname and time intervals')
	last_30_days_counts, last_15_days_counts, last_7_days_counts = count_events_by_hostname_with_timeframes(events)

	print('Adding event counts to agents list')
	agents = add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts)

	print('Adding last checkin days ago to agents list')
	agents = add_lastcheckin_days_ago(agents)

	print('Loading agents list into a DataFrame')
	agents_df = pandas.DataFrame(agents)

	columns_to_remove = ['freespace', 'groupid', 'domain', 'ip', 'status', 'username']
	print('Removing irrelevant columns', columns_to_remove)
	agents_df.drop(columns_to_remove, axis=1, inplace=True)

	print('Re-arranging columns in the dataframe')
	agents_df = move_df_column_to_position(agents_df, 'hostname', 0)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_last_30_days', 1)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_last_15_days', 2)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_last_7_days', 3)
	agents_df = move_df_column_to_position(agents_df, 'lastcheckin_days_ago', 4)

	print('Analysis complete, beginning export')

	print('Calculating export filename')
	output_filename = server_name.split('.')[0] + '_' + group['name'].replace(' ','-') + '_enforcement_readiness_' + timestamp_to_str + '.xlsx'
	print('Results will be written to', output_filename)

	print('Exporting data')
	with pandas.ExcelWriter(output_filename) as writer:
		agents_df.to_excel(writer, index=False, sheet_name='Enforcement Readiness', na_rep='')
		print('Adjusting column widths in the exported file')
		for column in agents_df:
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets['Enforcement Readiness'].set_column(col_idx, col_idx, column_width)
	print('Done exporting data')

	end_time = time.time()
	print(datetime.datetime.fromtimestamp(end_time).strftime('%H:%M:%S'), 'Done')
	total_runtime = end_time - start_time
	print(f'Total runtime: {total_runtime:.2f} seconds to process {days} days of events (quantity: {len(events)}) and {len(agents)} agents')

if __name__ == '__main__':
	main()