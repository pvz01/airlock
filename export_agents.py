# Example of how to bulk export the list of Agents to disk in MS Excel format
# 
# Use this command to install prerequisites:
#     pip install requests datetime pandas xlsxwriter openpyxl

import json, sys, requests, datetime, pandas, xlsxwriter, openpyxl, dateutil

#prompt for config
server_fqdn = input('Server: ')
api_key = input('API key: ')
verify_ssl = input('Verify SSL [yes | no]: ')

#calculate base configuration used for requests to server
base_url = 'https://' + server_fqdn + ':' + str(3129) + '/'
headers = {'X-APIKey': api_key}

#process SSL configuration
if verify_ssl.lower() == 'yes':
	verify_ssl = True
else:
	verify_ssl = False
	import urllib3
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#get list of groups
request_url = f'{base_url}v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
if response.status_code != 200:
	print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
	sys.exit(0)
groups = response.json()['response']['groups']
print('INFO: Found', len(groups), 'groups on the server')

#create a dictionary to map groupid to name
group_mapping = {group['groupid']: group['name'] for group in groups}

#update the group names with parent names
for group in groups:
    parent_name = group_mapping.get(group['parent'])
    if parent_name:
        group['name'] = f"{parent_name}\\{group['name']}"

#add policy mode to groups list
print('INFO: Checking policymode (audit | enforcement) for the groups')
print(f"{'policymode'.ljust(15, ' ')}\tgroupname")
print('------------------------------------')
for group in groups:
	request_url = f'{base_url}v1/group/policies'
	payload = {'groupid': group['groupid']}
	response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
	auditmode = (1 == int(response.json()['response']['auditmode']))
	if auditmode:
		group['policymode'] = 'audit'
	else:
		group['policymode'] = 'enforcement'
	print(f"{group['policymode'].ljust(15, ' ')}\t{group['name']}")
        
#ask user which group they want to export
for index, item in enumerate(groups):
	print(f'{index+1}: {item["name"]}')
group_selection = input('Which group do you want to export? Enter a single number, or press return to export all: ')
if group_selection == '':
	print('INFO: You chose to export all groups')
	groupname = 'all-groups'
	payload = {}
else:
	index = int(group_selection)-1
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
	print('INFO:', len(agents), 'records returned')

	#add group name to agent list
	print('INFO: Appending groupname column to agent list')
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['groupname'] = group['name']

	#add mode to agent list
	print('INFO: Appending policymode column to agent list')
	for agent in agents:
		for group in groups:
			if agent['groupid'] == group['groupid']:
				agent['policymode'] = group['policymode']
				
	#add days offline
	print('INFO: Appending daysoffline column to agent list')
	now = datetime.datetime.now(datetime.timezone.utc)
	for agent in agents:
		lastcheckin = dateutil.parser.parse(agent['lastcheckin'])
		agent['daysoffline'] = (now - lastcheckin).days


	#convert data to pandas dataframe for subsequent manipulation and export
	print('INFO: Converting agent list to dataframe')
	agents_df = pandas.DataFrame(agents)

	#replace status with human-readable values
	print('INFO: Converting status values to human-readable strings')
	status_mapping = {0: 'offline', 1: 'online', 3: 'safemode'}
	agents_df['status'] = agents_df['status'].replace(status_mapping)

	#sort data
	sort_by_column_names = ['groupname', 'hostname']
	print('INFO: Sorting data by', sort_by_column_names)
	agents_df.sort_values(by=sort_by_column_names, inplace=True)
	
	#re-arrange columns
	column_order = ['hostname', 'domain', 'clientversion', 'policyversion', 'policymode', 'os', 'groupname', 'lastcheckin', 'daysoffline', 'ip', 'status', 'agentid', 'groupid', 'username', 'freespace']
	print('INFO: Re-arranging columns using column_order', column_order)
	for index, columnname in enumerate(column_order):
		column = agents_df.pop(columnname)
		agents_df.insert(index, columnname, column)

	#calculate file name for export
	print('INFO: Calculating file name for export')
	groupname = groupname.replace("\\", "-").replace(" ", "-")
	server_fqdn = server_fqdn.replace(".", "-")
	file_name = f'airlock_agents_{server_fqdn}_{groupname}_{datetime.datetime.today().strftime("%Y-%m-%d_%H.%M")}.xlsx'

	#export data
	print('INFO: Exporting data to', file_name)
	with pandas.ExcelWriter(file_name) as writer:
		agents_df.to_excel(writer, index=False, sheet_name='Airlock Agents', na_rep='')

		#resize columns to fit the data
		print('INFO: Resizing columns to fit exported data')
		for column in agents_df:
			column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
			col_idx = agents_df.columns.get_loc(column)
			writer.sheets['Airlock Agents'].set_column(col_idx, col_idx, column_width)
