# export_agents_with_summary.py
# Version: 1.0
# Last updated: 2024-11-18
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# This is an example of how to export the inventory of registered agents on an Airlock
# Server in Microsoft Excel format including pre-calculated summaries of the data, 
# removing the need to create a PivotTable or do other logic post-export for the
# most common use cases. It includes an example of how to do "joins" by correlating
# data from multiple API endpoints. This script also supports the ability to calculate
# endpoint categories based on custom criteria and to use categories when summarizing
# the data.
#
# This script requires an API key for a user in a group with the following API role
# permissions:
#     agent/find
#     group
#     group/policies
#
# This script reads configuration from a YAML file. To create one, use a text editor
# of your choice and follow the syntax below, then save it as 'airlock.yaml' in the same
# directory as this PY script. The server_name and api_key are required. The remainder
# of the content is only required if you want to use the optional feature to categorize
# your agents based on your custom criteria. If not, just remove and include the first
# two lines only.
'''
server_name: foo.bar.managedwhitelisting.com
api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
categories:
  - name: Lab Machines
    hostname_startswith: lab-
  - name: Developers
    hostname_substring: 
      start: 3
      end: 6
      match: dev
  - name: Servers
    os_contains: windows server
  - name: General User Population
'''

import json, sys, requests, datetime, pandas, xlsxwriter, openpyxl, dateutil, urllib3, yaml, os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(file_name='airlock.yaml'):
	print('Reading configuration from', file_name)
	if not os.path.exists(file_name):
		print('Error: config file', file_name, 'does not exist')
		sys.exit(1)

	with open(file_name, 'r') as file:
		config = yaml.safe_load(file)

	global server_name
	global request_headers
	global categories

	server_name = config.get('server_name', None)
	if not server_name:
		print('Error: server_name is missing in the config file')
		sys.exit(1)
	print('Read server_name', server_name)
	
	api_key = config.get('api_key', None)
	if not api_key:
		print('Error: api_key is missing in the config file')
		sys.exit(1)
	print(f"Read api_key {'*' * (len(api_key) - 4)}{api_key[-4:]}")
	request_headers = {'X-ApiKey': api_key}
	
	categories = config.get('categories', None)
	if categories:
		print('Read', len(categories), 'categories')
	else:
		print('No categories provided')

	return config

def get_agents():
	print('Getting agents list from server')
	request_url = f"https://{server_name}:3129/v1/agent/find"
	response = requests.post(request_url, headers=request_headers, json={}, verify=False)
	print(request_url, response)
	agents = response.json()['response']['agents']
	print('Downloaded', len(agents), 'agents')
	return agents

def get_groups():
	print('Getting groups list from server')
	request_url = f"https://{server_name}:3129/v1/group"
	response = requests.post(request_url, headers=request_headers, verify=False)
	print(request_url, response)
	groups = response.json()['response']['groups']
	print('Downloaded', len(groups), 'policy groups')
	return groups

def add_policymode_to_groups(groups):
	print('Adding policymode to groups list')
	for group in groups:
		request_url = f"https://{server_name}:3129/v1/group/policies?groupid={group['groupid']}"
		response = requests.post(request_url, headers=request_headers, verify=False)
		print(request_url, response)
		if (1 == int(response.json()['response']['auditmode'])):
			group['policymode'] = 'Audit Mode'
		else:
			group['policymode'] = 'Enforcement Mode'
	return groups

def add_parent_to_group_names(groups):
	print('Adding parent group as prefix on group name field in groups list')
	group_mapping = {group['groupid']: group['name'] for group in groups}
	for group in groups:
		parent_name = group_mapping.get(group['parent'])
	if parent_name:
		group['name'] = f"{parent_name}\\{group['name']}"
	return groups

def add_group_name_to_agents(agents, groups):
	print('Adding groupname to agents list')
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['groupname'] = group['name']
	return agents

def add_policymode_to_agents(agents, groups):
	print('Adding policymode to agents list')
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['policymode'] = group['policymode']
	return agents

def add_days_offline_to_agents(agents):
	now = datetime.datetime.now(datetime.timezone.utc)
	print('Addding days offline to agent list by comparing lastcheckin to', now)
	for agent in agents:
		lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
		agent['daysoffline'] = (now - lastcheckin).days
	return agents

def convert_agent_status_to_human_readable(agents):
	print('Converting agent status values from numeric to human-readable')
	for agent in agents:
		if agent['status'] == 0:
			agent['status'] = 'offline'
		elif agent['status'] == 1:
			agent['status'] = 'online'
		elif agent['status'] == 3:
			agent['status'] = 'safemode'
	return agents

def get_category(agent):
    hostname = agent['hostname'].lower()
    os_name = agent['os'].lower()
    for category in categories:
        if 'hostname_startswith' in category and hostname.startswith(category['hostname_startswith']):
            return category['name']
        if 'hostname_contains' in category and category['hostname_contains'] in hostname:
            return category['name']
        if 'hostname_endswith' in category and hostname.endswith(category['hostname_endswith']):
            return category['name']
        if 'hostname_substring' in category:
            start_idx = category['hostname_substring']['start']
            end_idx = category['hostname_substring']['end']
            substring_match = category['hostname_substring']['match']
            if hostname[start_idx:end_idx] == substring_match:
                return category['name']
        if 'os_contains' in category and category['os_contains'] in os_name:
            return category['name']
    return 'Standard'

def calculate_export_filename():
	print('Calculating file name to be used for export')
	server_alias = server_name.split('.')[0]
	now = datetime.datetime.now(datetime.timezone.utc)
	timestamp = now.strftime("%Y-%m-%d_%H-%M_utc")
	export_file_name = f"airlock_agents_{server_alias}_{timestamp}.xlsx"
	print('Data will be exported to', export_file_name)
	return export_file_name

def export_dataframe_to_excel(agents_df, export_filename, summarize_by=None):
	with pandas.ExcelWriter(export_filename) as writer:
		agents_df.to_excel(writer, index=False, sheet_name='Data', na_rep='')
		for column in agents_df:
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets['Data'].set_column(col_idx, col_idx, column_width)
		if summarize_by:
			for field in summarize_by:
				if field in agents_df.columns:
					print('Summarizing data by', field)
					summary_df = agents_df[field].value_counts().reset_index()
					summary_df.columns = [field, 'Count']
					summary_sheet_name = f'summary_by_{field}'
					summary_df.to_excel(writer, index=False, sheet_name=summary_sheet_name)
					print('Re-sizing columns for', summary_sheet_name)
					for column in summary_df:
						column_width = max(summary_df[column].astype(str).map(len).max(), len(column)) + 1
						col_idx = summary_df.columns.get_loc(column)
						writer.sheets[summary_sheet_name].set_column(col_idx, col_idx, column_width)

read_config()
agents = get_agents()
groups = get_groups()
groups = add_policymode_to_groups(groups)
groups = add_parent_to_group_names(groups)
agents = add_group_name_to_agents(agents, groups)
agents = add_policymode_to_agents(agents, groups)
agents = add_days_offline_to_agents(agents)
agents = convert_agent_status_to_human_readable(agents)

if categories:
	for agent in agents:
		agent['category'] = get_category(agent)
		agent['category-policymode'] = f"{agent['category']} - {agent['policymode']}"

print('Loading agents list into a DataFrame')
agents_df = pandas.DataFrame(agents)

sort_by_columns = ['groupname', 'hostname']
print('Sorting DataFrame by', sort_by_columns)
agents_df.sort_values(by=sort_by_columns, inplace=True)

column_order = ['hostname', 'domain', 'clientversion', 'policyversion', 'policymode', 'os', 'groupname', 'lastcheckin', 'daysoffline', 'ip', 'status', 'agentid', 'groupid', 'username', 'freespace']
if categories:
	column_order.insert(1, 'category')
	column_order.insert(2, 'category-policymode')

print('Arranging column order in DataFrame to be', column_order)
for index, columnname in enumerate(column_order):
	column = agents_df.pop(columnname)
	agents_df.insert(index, columnname, column)

print('Exporting data')
export_filename = calculate_export_filename()
summarize_by = ['groupname', 'policymode']
if categories:
	summarize_by.insert(0, 'category-policymode')
	summarize_by.insert(1, 'category')
export_dataframe_to_excel(agents_df, export_filename, summarize_by=summarize_by)
print('Done')