# Example of how to generate MS Excel format report on recent untrusted executions
# which can be used to determine readiness to promote agents to enforcement mode
# on a per-agent basis (for example using move_agents.py).
# 
# Use this command to install prerequisites:
#     pip install requests datetime pandas xlsxwriter openpyxl

#required third-party libraries
import requests, json, sys, datetime, dateutil, pandas, xlsxwriter, openpyxl

#option to disable SSL certificate verification when running against a non-production server
is_lab_server = True
if is_lab_server:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	print('WARNING: SSL verification is disabled due to is_lab_server being set to True')
else:
	verify_ssl = True
	
#create global variables
base_url = ''
headers = {}

#define a series of functions used for the analysis
def get_groups():
	request_url = f'{base_url}v1/group'
	response = requests.post(request_url, headers=headers, verify=verify_ssl)
	if response.status_code == 200:
		return response.json()['response']['groups']
	else:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
		sys.exit(0)

def choose_group(groups, prompt_message):
	print('\nIndex \tName \tGroup ID \tParent Group ID')
	for index, item in enumerate(groups):
		print(index, '\t', item['name'], '\t', item['groupid'], '\t', item['parent'])
	index = int(input(prompt_message))
	return groups[index]

def get_agents(group):
	request_url = f'{base_url}v1/group/agents'
	payload = {'groupid': group['groupid']}
	response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
	if response.status_code == 200:
		return response.json()['response']['agents']
	else:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
		sys.exit(0)
	
def add_group_name_to_agent_list(agents,groups):
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['group_name'] = group['name']
	return agents

def add_lastcheckin_days_ago(agents):
	now = datetime.datetime.now(datetime.timezone.utc)
	for agent in agents:
		lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
		agent['lastcheckin_days_ago'] = (now - lastcheckin).days
	return agents

def add_execution_counts(agents, intervals):
	counter = 1
	for agent in agents:
		print('INFO: Gathering execution data for agent', counter, 'of', len(agents), agent['hostname'])
		for interval in intervals:
			print('\tLast', interval, 'days')
			new_column = f'untrusted_executions_{str(interval)}_days'
			execution_count = get_untrusted_execution_count(agent['hostname'], interval)     
			agent[new_column] = execution_count
		counter += 1
	return agents
	
def move_df_column_to_position(df, column_name, new_position):
	column_to_move = df.pop(column_name)
	df.insert(new_position, column_name, column_to_move)
	return df

def add_audit_mode_to_group_list(groups):
	counter = 1
	for group in groups:
		print('INFO: Analyzing group', counter, 'of', len(groups), group['name'])
		request_url = f'{base_url}v1/group/policies'
		payload = {'groupid': group['groupid']}
		response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
		if response.status_code == 200:
			auditmode = int(response.json()['response']['auditmode'])
			if auditmode == 1:
				group['auditmode'] = True
			else:
				group['auditmode'] = False
		else:
			print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
			sys.exit(0)
		counter += 1
	return groups

def filter_group_list(groups, auditmode):
	filtered_groups = []
	for group in groups:
		if group['auditmode'] == auditmode:
			filtered_groups.append(group)
	return filtered_groups

def get_untrusted_execution_count(hostname, days):
	request_url = f'{base_url}v1/getexechistory'
	payload = {'category': 'audit',
			   'hostname': hostname,
			   'Datefrom': (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime('%Y-%m-%d'), 
			   'Dateto': (datetime.datetime.utcnow() + datetime.timedelta(1)).strftime('%Y-%m-%d') #We want to include data from today, so set max timestamp to Midnight tonight (today plus 1)
			  }
	response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
	if response.status_code != 200:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
		sys.exit(0)
	else:
		exechistory = response.json()['response']['exechistory']
		if exechistory != None:
			return len(exechistory)
		else:
			return 0


#main method that is used at runtime
def main():

	global base_url
	global headers

	#prompt for config
	server_fqdn = input('Enter server fqdn: ')
	server_port = input('Enter server port, or press return to accept the default (3129): ')
	if server_port == '':
		server_port = 3129
	api_key = input('Enter API key: ')

	#calculate base configuration used for requests to server
	base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
	headers = {'X-APIKey': api_key}

	print('INFO: Getting list of groups from', server_fqdn)
	groups = get_groups()
	print('INFO: Found', len(groups), 'total groups')

	print('INFO: Getting policy data for each group to determine which are Audit Mode')
	groups = add_audit_mode_to_group_list(groups)

	print('INFO: Filtering group list')
	groups = filter_group_list(groups, auditmode=True)
	print('INFO: Found', len(groups), 'groups with an Audit Mode policy on', server_fqdn)

	group = choose_group(groups, '\nEnter the Index of the group that you want to analyze for enforcement readiness: ')

	print('INFO: Getting list of agents in group', group['name'])
	agents = get_agents(group)
	if len(agents) == 0:
		print('ERROR: No agents found')
		sys.exit(0)
	print('INFO: Found', len(agents), 'agents')

	print('INFO: Adding group name to agent list')
	agents = add_group_name_to_agent_list(agents, groups)

	print('INFO: Calculating how many days ago the last checkin was for each agent and adding it to agent list')
	agents = add_lastcheckin_days_ago(agents)

	# This area of code is relatively inefficient at the moment since it asks for some of the event data 3X 
	# (the 7 day data is a subset of the 15 day data which is a subset of the 30 day data). Runtime could be 
	# reduced if we pulled data 1X for the largest data set and then did downstream filtering locally. But for
	# simplicity, leaving it as-is for now. I anticipate that total runtime is going to be reasonable for all
	# but the very largest data sets. Can always revisit in a later version.
	intervals = [30, 15, 7]
	print('INFO: Getting untrusted execution counts for intervals', intervals, '***This may take a while***')
	agents = add_execution_counts(agents, intervals)
	print('INFO: Done gathering data')

	print('INFO: Converting the data to a DateFrame for subsequent manipulation and export')
	agents_df = pandas.DataFrame(agents)

	columns_to_remove = ['freespace', 'groupid', 'domain', 'ip', 'status', 'username']
	print('INFO: Removing irrelevant columns:', columns_to_remove)
	agents_df.drop(columns_to_remove, axis=1, inplace=True)

	print('INFO: Re-arranging columns')
	agents_df = move_df_column_to_position(agents_df, 'hostname', 0)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_30_days', 1)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_15_days', 2)
	agents_df = move_df_column_to_position(agents_df, 'untrusted_executions_7_days', 3)
	agents_df = move_df_column_to_position(agents_df, 'lastcheckin_days_ago', 4)

	print('INFO: Calculating file name for export')
	file_name = f"airlock_enforcement_readiness_{server_fqdn}_{group['name']}_{datetime.datetime.today().strftime('%Y-%m-%d_%H.%M')}.xlsx"
	print(f'\t{file_name}')

	print('INFO: Exporting data to disk')
	with pandas.ExcelWriter(file_name) as writer:
		agents_df.to_excel(writer, index=False, sheet_name='Enforcement Readiness', na_rep='')
		print('INFO: Adjusting column widths')
		for column in agents_df:
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets['Enforcement Readiness'].set_column(col_idx, col_idx, column_width)

	print('Done.')


#when the file is run (python filename.py), invoke the main() method
if __name__ == "__main__":
	main()
