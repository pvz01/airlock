# Example of how to bulk export the list of Agents to disk in MS Excel format
# 
# Use this command to install prerequisites:
#     pip install requests datetime pandas xlsxwriter openpyxl

import json, sys, requests, datetime, pandas, xlsxwriter, openpyxl

#prompt for config
server_fqdn = input('Enter server fqdn: ')
server_port = input('Enter server port, or press return to accept the default (3129): ')
if server_port == '':
	server_port = 3129
api_key = input('Enter API key: ')

#option to disable SSL certificate verification when running against a non-prod server
is_lab_server = False
if is_lab_server:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
	verify_ssl = True

#calculate base configuration used for requests to server
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}

#get list of groups
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

#ask user which group they want to export
for index, item in enumerate(groups):
	print(f'{index}: {item["name"]} ({item["groupid"]})')
group_selection = input('Which group do you want to export? Enter a single number, or press return to export all: ')
if group_selection == '':
	print('INFO: You chose to export all groups')
	groupname = 'all_groups'
	payload = {}
else:
	index = int(group_selection)
	print('INFO: You chose', groups[index])
	groupname = groups[index]['name']
	payload = {'groupid': groups[index]['groupid']}

#get agent list from server
print('INFO: Querying server for agents with search parameters', payload)
request_url = f'{base_url}v1/agent/find'
response = requests.post(request_url, headers=headers, verify=verify_ssl, json=payload)
agents = response.json()['response']['agents']
if agents == None:
	print('ERROR: No records returned')
	sys.exit(0)
else:
	print(len(agents), 'records returned')

	#add group name(s) to agent list
	print('INFO: Appending group name column to agent list')
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['group_name'] = group['name']

	#convert data to pandas dataframe for subsequent manipulation and export
	agents_df = pandas.DataFrame(agents)

	#sort data by hostname
	agents_df.sort_values(by=['hostname'], inplace=True)

	#calculate file name for export
	file_name = f'airlock_agents_{server_fqdn}_{groupname}_{datetime.datetime.today().strftime("%Y-%m-%d_%H.%M")}.xlsx'

	#export data
	print('INFO: Exporting data to', file_name)
	with pandas.ExcelWriter(file_name) as writer:
		agents_df.to_excel(writer, index=False, sheet_name='Airlock Agents', na_rep='')

		#resize columns to fit the data
		for column in agents_df:
			#column_width = 100
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets['Airlock Agents'].set_column(col_idx, col_idx, column_width)
