# enforcement_readiness.py
# Version: 2.1
# Last updated: 2024-08-29
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to generate MS Excel format report on recent untrusted executions
# which can be used to determine readiness to promote agents to enforcement mode
# on a per-hostname basis (for example by using move_agents.py).
#
# Known limitations:
# 1. If you have duplicate hostnames in your environment, the sum of events for all 
#    agents with the same hostname will be returned for all agents with that hostname.
# 2. If you have duplicate hostnames in your environment, all agents with the same
#    hostname will report the same value for installed_days_ago which will reflect
#    the most recent registration for any device with that hostname.

import requests, json, urllib3, datetime, time, yaml, pandas, bson, dateutil.parser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(file_name):
	"""
	Reads the YAML configuration file.

	Parameters:
	file_name (str): The name of the configuration file.

	Returns:
	dict: The configuration settings as a dictionary.
	"""
	with open(file_name, 'r') as file:
		config = yaml.safe_load(file)
	print('Read config from', file_name, 'for server', config['server_name'])
	return config

def objectid_n_days_ago(n):
	"""
	Calculates the MongoDB ObjectId corresponding to a timestamp n days ago.

	Parameters:
	n (int): Number of days ago.

	Returns:
	bson.ObjectId: The ObjectId corresponding to the calculated timestamp.
	"""
	datetime_n_days_ago = datetime.datetime.now() - datetime.timedelta(days=n)
	timestamp = int(datetime_n_days_ago.timestamp())
	objectid_hex = hex(timestamp)[2:] + '0000000000000000'
	return bson.ObjectId(objectid_hex)

def get_groups(server_name, api_key):
	"""
	Fetches the list of groups from the server.

	Parameters:
	server_name (str): The server name.
	api_key (str): The API key for authentication.

	Returns:
	list: A list of groups.
	"""
	request_url = 'https://' + server_name + ':3129/v1/group'
	request_headers = {'X-APIKey': api_key}
	response = requests.post(request_url, headers=request_headers, verify=False)
	return response.json()['response']['groups']

def add_audit_mode_to_group_list(groups, server_name, api_key):
	"""
	Adds audit mode status to each group in the list.

	Parameters:
	groups (list): List of groups.
	server_name (str): The server name.
	api_key (str): The API key for authentication.

	Returns:
	list: The list of groups with audit mode status added.
	"""
	group_index = 1
	for group in groups:
		print('Analyzing group', group_index, 'of', len(groups), group['name'], end=' ')
		request_url = 'https://' + server_name + ':3129/v1/group/policies'
		request_headers = {'X-APIKey': api_key}
		request_body = {'groupid': group['groupid']}
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		auditmode = int(response.json()['response']['auditmode'])
		group['auditmode'] = (auditmode == 1)
		print('[Audit]' if auditmode == 1 else '[Enforcement]')
		group_index += 1
	return groups

def filter_group_list(groups, auditmode):
	"""
	Filters the group list based on audit mode.

	Parameters:
	groups (list): List of groups.
	auditmode (bool): Filter for audit mode.

	Returns:
	list: Filtered list of groups.
	"""
	return [group for group in groups if group['auditmode'] == auditmode]

def choose_group(groups, prompt_message, server_name):
	"""
	Prompts the user to choose a group from the list.

	Parameters:
	groups (list): List of groups.
	prompt_message (str): The prompt message to display.
	server_name (str): The server name.

	Returns:
	dict: The selected group.
	"""
	print('These are', len(groups), 'Audit Mode groups on', server_name)
	for index, item in enumerate(groups):
		print(index+1, '\t', item['name'])
	index = int(input(prompt_message)) - 1
	return groups[index]

def get_agents_in_group(group, server_name, api_key):
	"""
	Fetches the list of agents in the specified group.

	Parameters:
	group (dict): The group information.
	server_name (str): The server name.
	api_key (str): The API key for authentication.

	Returns:
	list: The list of agents in the group.
	"""
	request_url = 'https://' + server_name + ':3129/v1/group/agents'
	request_headers = {'X-APIKey': api_key}
	request_body = {'groupid': group['groupid']}
	response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
	return response.json()['response']['agents']

def add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts):
	"""
	Adds untrusted execution counts to each agent.

	Parameters:
	agents (list): List of agents.
	last_30_days_counts (dict): Execution counts for the last 30 days.
	last_15_days_counts (dict): Execution counts for the last 15 days.
	last_7_days_counts (dict): Execution counts for the last 7 days.

	Returns:
	list: The list of agents with execution counts added.
	"""
	for agent in agents:
		agent['untrusted_30d'] = last_30_days_counts.get(agent['hostname'], 0)
		agent['untrusted_15d'] = last_15_days_counts.get(agent['hostname'], 0)
		agent['untrusted_7d'] = last_7_days_counts.get(agent['hostname'], 0)
	return agents

def add_checkin_age(agents):
	"""
	Adds the number of days since the last check-in to each agent.

	Parameters:
	agents (list): List of agents.

	Returns:
	list: The list of agents with the last check-in days added.
	"""
	now = datetime.datetime.now(datetime.timezone.utc)
	for agent in agents:
		lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
		agent['checkin_age'] = (now - lastcheckin).days
	return agents

def get_exechistories_for_group(group, server_name, api_key, types=[2], checkpoint='000000000000000000000000'):
	"""
	Fetches execution histories for the specified group.

	Parameters:
	group (dict): The group information.
	server_name (str): The server name.
	api_key (str): The API key for authentication.
	types (list): List of event types to fetch.
	checkpoint (str): The checkpoint for pagination.

	Returns:
	list: The list of execution history events.
	"""
	request_url = 'https://' + server_name + ':3129/v1/logging/exechistories'
	request_headers = {'X-APIKey': api_key}
	request_body = {
		'type': types,  # the default [2] denotes "Untrusted Execution [Audit]"
		'checkpoint': checkpoint,
		'policy': [group['name']]
	}

	all_events = []
	while True:
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		events = response.json()['response']['exechistories']
		print(request_url, request_body, 'returned', len(events), 'records')
		all_events += events

		if len(events) == 10000:
			request_body['checkpoint'] = events[-1]['checkpoint']
		else:
			break

	return all_events

def count_events_by_hostname_with_timeframes(events):
	"""
	Counts the number of events by hostname within different timeframes.

	Parameters:
	events (list): List of events.

	Returns:
	tuple: Three dictionaries containing counts for the last 30, 15, and 7 days.
	"""
	last_30_days_counts = {}
	last_15_days_counts = {}
	last_7_days_counts = {}

	current_time = datetime.datetime.now(datetime.timezone.utc)
	last_30_days_threshold = current_time - datetime.timedelta(days=30)
	last_15_days_threshold = current_time - datetime.timedelta(days=15)
	last_7_days_threshold = current_time - datetime.timedelta(days=7)

	for event in events:
		hostname = event.get('hostname')
		event_time = datetime.datetime.strptime(event.get('datetime'), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)

		if event_time >= last_30_days_threshold:
			last_30_days_counts[hostname] = last_30_days_counts.get(hostname, 0) + 1

		if event_time >= last_15_days_threshold:
			last_15_days_counts[hostname] = last_15_days_counts.get(hostname, 0) + 1

		if event_time >= last_7_days_threshold:
			last_7_days_counts[hostname] = last_7_days_counts.get(hostname, 0) + 1

	return last_30_days_counts, last_15_days_counts, last_7_days_counts

def get_server_activity_history(server_name, api_key, checkpoint='000000000000000000000000'):
	"""
	Fetches server activity history logs.

	Parameters:
	server_name (str): The server name.
	api_key (str): The API key for authentication.
	checkpoint (str): The checkpoint for pagination.

	Returns:
	list: The list of server activity history logs.
	"""
	request_url = 'https://' + server_name + ':3129/v1/logging/svractivities'
	request_headers = {'X-APIKey': api_key}
	request_body = {'checkpoint': checkpoint}

	all_svractivities = []
	while True:
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		svractivities = response.json()['response']['svractivities']
		print(request_url, request_body, 'returned', len(svractivities), 'records')
		all_svractivities += svractivities

		if len(svractivities) == 10000:
			request_body['checkpoint'] = svractivities[-1]['checkpoint']
		else:
			break

	return all_svractivities

def get_last_registrations_per_hostname(server_activity_logs):
	"""
	Extracts the most recent registration timestamps per hostname.

	Parameters:
	server_activity_logs (list): List of server activity logs.

	Returns:
	dict: A dictionary mapping hostnames to their most recent registration timestamp.
	"""
	results = {}
	for entry in server_activity_logs:
		if entry['task'] == 'Client Operation' and entry['user'] == 'SYSTEM':
			if entry['description'].startswith('New agent'):
				hostname = entry['description'].split()[2].lower()  # hostname is 3rd word in the description field
				timestamp = dateutil.parser.parse(entry['datetime'])
				if hostname not in results or timestamp > results[hostname]:
					results[hostname] = timestamp
	return results

def add_install_age(agents, registration_timestamps, max_days):
	"""
	Adds the number of days since installation to each agent.

	Parameters:
	agents (list): List of agents.
	registration_timestamps (dict): Registration timestamps per hostname.
	max_days (int): The maximum days to assign if no registration timestamp is found.

	Returns:
	list: The list of agents with installation days added.
	"""
	now = datetime.datetime.now(datetime.timezone.utc)
	for agent in agents:
		registration_timestamp = registration_timestamps.get(agent['hostname'].lower())
		if registration_timestamp is None: 
			agent['install_age'] = f'{str(max_days)}+'
		else:
			agent['install_age'] = (now - registration_timestamp).days
	return agents

def collect_data(server_name, api_key, group, days):
	"""
	Collects agents, execution history events, and server activity logs.

	Parameters:
	server_name (str): The server name.
	api_key (str): The API key for authentication.
	group (dict): The group information.
	days (int): The number of days of data to collect.

	Returns:
	tuple: A tuple containing the list of agents, events, server activity logs, 
		   the start time of the collection, and the formatted timestamp.
	"""
	start_time = time.time()
	print('Beginning data collection')

	agents = get_agents_in_group(group, server_name, api_key)
	print('Downloaded', len(agents), 'agents')

	print('Calculating database checkpoint from', days, 'days ago to use for downloading events and server activity logs with a datetime')
	checkpoint = str(objectid_n_days_ago(days))
	print('Checkpoint is', checkpoint)

	events = get_exechistories_for_group(group, server_name, api_key, checkpoint=checkpoint)
	print('Downloaded', len(events), 'events')

	sah_logs = get_server_activity_history(server_name, api_key, checkpoint=checkpoint)
	print('Downloaded', len(sah_logs), 'server activity history logs')

	print('Data collection is complete')

	return agents, events, sah_logs, start_time

def main():
	"""
	Main function to run the enforcement readiness assessment.
	"""
	readme_message = """
Welcome to the PVZ's Airlock Enforcement Readiness Assessment tool. This tool is an example of how to
generate an Excel-readable spreadsheet with key data points to assist with assessing which computers
in your environment are relatively low versus relatively high risk to promote from Audit Mode to 
Enforcement Mode. To accomplish this, it exports all events in the last 30 days from your chosen Audit 
Mode policy, summarizes them by hostname, and then exports this along with a list of hostnames in that 
policy. It also adds columns which indicate how many days ago each agent last connected to the server
and how long ago the most recent registation (new install) for that hostname occured.

This script makes no changes to your environment and makes no specific recommendation on what to move
to enforcement. Instead, it equips you to do "what if" scenarios in Excel, for example if you were to
filter the results on 

  untrusted_15d < 5
  -and-
  install_age > 21
  -and-
  checkin_age < 3

you would be left with a list of devices which have been installed 3+ weeks, had minimal events in
the last 2+ weeks, and have checked in (and therefore uploaded any new events) within the last 2 days.
Many customers consider that devices matching this criteria are quite low risk to move to Enforcement 
Mode and use same or similar criteria to promote devices.

This tool reads server configuration from a YAML configuration file. Use a text editor of your choice 
to create a configuration file matching the syntax below and place it in the same folder as the PY
script.

server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey

The API key provided in the YAML must have permission to the following API endpoints:
	group
	group/policies
	group/agents
	logging/exechistories
	logging/svractivities

This script is published under the GNU General Public License v3.0 and is intended as a working example 
of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

	"""
	print(readme_message)

	config_file_name = input('Enter the name of a YAML file containing server configuration: ')
	config = read_config(config_file_name)
	server_name = config['server_name']
	api_key = config['api_key']
	days = 30

	print('Getting list of groups from server')
	groups = get_groups(server_name, api_key)

	print('Reading policy for each group to determine Audit vs Enforcement Mode')
	groups = add_audit_mode_to_group_list(groups, server_name, api_key)

	print('Filtering group list to remove Enforcement Mode groups')
	groups = filter_group_list(groups, True)

	group = choose_group(groups, 'Which group do you want to perform analysis on? Enter number and press return: ', server_name)

	agents, events, sah_logs, start_time = collect_data(server_name, api_key, group, days)

	print('Summarizing events by hostname and time intervals')
	last_30_days_counts, last_15_days_counts, last_7_days_counts = count_events_by_hostname_with_timeframes(events)

	print('Analyzing server activity logs to find most recent registration per hostname')
	registration_timestamps = get_last_registrations_per_hostname(sah_logs)

	print('Adding untrusted execution counts to agents list')
	agents = add_execution_counts(agents, last_30_days_counts, last_15_days_counts, last_7_days_counts)

	print('Adding checkin_age to agents list')
	agents = add_checkin_age(agents)

	print('Adding install_age to agents list')
	agents = add_install_age(agents, registration_timestamps, max_days=days)

	print('Loading results into a pandas dataframe')
	agents_df = pandas.DataFrame(agents)

	columns_to_remove = ['freespace', 'groupid', 'domain', 'ip', 'status', 'username', 'clientversion', 'policyversion']
	print('Dropping columns', columns_to_remove)
	agents_df.drop(columns_to_remove, axis=1, inplace=True)

	column_order = ['hostname', 'untrusted_30d', 'untrusted_15d', 'untrusted_7d', 'checkin_age', 'install_age']
	print('Reordering columns to be', column_order)
	agents_df = agents_df[column_order]

	print('Analysis and data maniputation complete')

	output_filename = f"{server_name.split('.')[0]}_{group['name'].replace(' ', '-')}_Enforcement_Readiness_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d_%H-%M_UTC')}.xlsx"
	print('Exporting data to', output_filename)
	with pandas.ExcelWriter(output_filename) as writer:
		agents_df.to_excel(writer, index=False, sheet_name=group['name'], na_rep='')
		print('Auto-sizing column width on exported file to fit exported data')
		for column in agents_df:
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets[group['name']].set_column(col_idx, col_idx, column_width)
	
	print('Calculating runtime and other metrics')
	end_time = time.time()
	total_runtime = end_time - start_time
	hours, remainder = divmod(total_runtime, 3600)
	minutes, seconds = divmod(remainder, 60)
	formatted_time = f'{int(hours):02}:{int(minutes):02}:{int(seconds):02}'
	print(f'Total runtime was {formatted_time} to process {days} days of events (quantity: {"{:,}".format(len(events))}), {days} days of server activity logs (quantity: {"{:,}".format(len(sah_logs))}), and {"{:,}".format(len(agents))} agents.')
	
if __name__ == '__main__':
	main()
