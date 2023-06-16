# Description:
# Example of how to bulk export the list of Agents to disk in MS Excel format


#required third-party libraries (use 'pip install libraryname' to install if you get an error)
import requests, json, sys, datetime, pandas


#prompt for config
server_fqdn = input('Enter server fqdn: ')

server_port = input('Enter server port, or press return to accept the default (3129): ')
if server_port == '':
    server_port = 3129

api_key = input('Enter API key: ')

#set verify_ssl to False for lab environments without a proper SSL cert, otherwise set to True
verify_ssl = True
if not verify_ssl:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#calculate base configuration used for all requests
base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'
headers = {'X-APIKey': api_key}


#get agent data from server
request_url = f'{base_url}v1/agent/find'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
agents = response.json()['response']['agents']
print(len(agents), 'records returned')


#convert data to pandas dataframe for subsequent manipulation and export
agents_df = pandas.DataFrame(agents)


#sort data by hostname
agents_df.sort_values(by=['hostname'], inplace=True)


#calculate file name for export and print to console
file_name = f'airlock_agents_{server_fqdn}_{datetime.datetime.today().strftime("%Y-%m-%d_%H.%M")}.xlsx'
print('Exporting to disk as', file_name)


#export data to disk in Excel format and auto-size all columns
with pandas.ExcelWriter(file_name) as writer:
    agents_df.to_excel(writer, index=False, sheet_name='Airlock Agents', na_rep='')
    for column in agents_df:
        column_width = max(agents_df[column].astype(str).map(len).max(), len(column)) + 1
        col_idx = agents_df.columns.get_loc(column)
        writer.sheets['Airlock Agents'].set_column(col_idx, col_idx, column_width)