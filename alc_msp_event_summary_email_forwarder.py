# Example of how to collect and summarize event data for multiple tenants in Airlock
# Cloud and then forward it via Sendgrid. This can be useful for MSPs to run on a 
# recurring basis at some interval (every 10 minutes, every 4 hours, etcetera). At
# each iteration it will only report on new events received by the server after the
# previous iteration.
#
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
# Version: 1.1
# Last updated: 2023-12-26
#
# The script maintains persistence in configuration using a JSON file on disk, enabling
# you to run the script ad-hoc or using a scheduler of your choice (cron job, Windows
# Task Scheduler, or similar). When run it will ingest configuration, collect data,
# send a summary e-mail, and then write new configuration back to disk which includes
# relevant data useful for the next iteration such as the database checkpoint for each
# tenant. Before running the first time you must manually create and save a JSON config
# file using the template provided below. Provide the filename (including full-qualified
# path if not in the same directory) as the value of config_file_name below.
#
# In the interest of simplicity in providing a working example that is easy to understand,
# this script intentionally lacks exception handling. If an error occurs, expect Python
# to raise an unhandled exception and abort execution. Modified configuration is saved
# as the very last step, so in case of an error along the way, no harm is done and the
# script can be retried later. Consider using external tooling to monitor and alert on
# errors.

config_file_name = 'alc_msp_event_summary_email_forwarder.json'
debug_mode = False

# ---CONFIG FILE TEMPLATE --- 
'''
{
    "server_name": "au.appenforcement.com",
    "api_key": "your-airlock-cloud-api-key",
    "tenants": [
        {
            "name": "Tenant 1",
            "directoryid": "x",
            "Tenantid": "y"
        },
        {
            "name": "Tenant 2",
            "directoryid": "x",
            "Tenantid": "y"
        }
    ],
    "event_types": [
        "1",
        "6",
        "7"
    ],
    "email": {
        "from_email": "airlock@airlockdigital.com",
        "to_emails": [
            "user1@domain.com",
            "user2@domain.com"
        ],
        "mail_subject": "Airlock Cloud event summary",
        "sendgrid_api_key": "your-sendgrid-api-key",
        "dashboard_base_url": "https://portal.au.appenforcement.com"
    }
}
'''
# --- EVENT TYPE KEY (USE WHEN CONFIGURING EVENT_TYPES ARRAY IN CONFIG FILE) ---
'''
Note: When setting the event type array in the configuration file, use the numeric values shown below
	0 Trusted Execution
	1 Blocked Execution
	2 Untrusted Execution [Audit]
	3 Untrusted Execution [OTP]
	4 Trusted Path Execution
	5 Trusted Publisher Execution
	6 Blocklist Execution
	7 Blocklist Execution [Audit]
	8 Trusted Process Execution
'''

# -- IMPORT REQUIRED LIBRARIES --
import requests
import json
import datetime
import sendgrid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #suppress ssl warnings


# -- DEFINE A SERIES OF METHODS USED AT RUNTIME --

#reads json config file from disk and return it as a dictionary
def read_config():
	with open(config_file_name, 'r') as file:
		config = json.load(file)
	return config

#writes config dictionary to disk as json file
def write_config(config):
	with open(config_file_name, 'w') as file:
		json.dump(config, file, indent=4)

#gets new events from server for a tenant
def get_events(server_name, api_key, event_types, directoryid, tenantid, checkpoint):
	request_url = 'https://' + server_name + '/willard/v1/logging/exechistories'
	request_headers = {
			'UserApiKey': api_key,
			'directoryid': directoryid,
			'tenantID': tenantid,
			}
	request_body = {'type': event_types}
	collected_data = []
	while True:
		request_body['checkpoint'] = checkpoint
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		exechistories = response.json()['response']['exechistories']
		collected_data += exechistories
		if len(exechistories) == 10000:
			#large data set, first 10K returned, need to go back and ask for the rest
			checkpoint = exechistories[9999]['checkpoint']
		else:
			# We have all the data. Exit the while loop.
			break
	return collected_data

#converts a file hash into a HTML code which is a clickable link to VT search
def get_vt_link(md5):
	base_url = 'https://www.virustotal.com/gui/search/'
	full_url = base_url + md5
	html_code = f'<a href={full_url}>VT</a>'
	return html_code

#converts a file hash into HTML code which is a clickable link to the Airlock repository entry
def get_repo_link(tenant_id, dashboard_base_url, sha256):
	full_url = dashboard_base_url + '/tenant/' + tenant_id + '/repository?SHA256=' + sha256
	html_code = f'<a href={full_url}>ALD</a>'
	return html_code

#converts a tenant id into a clickable link into the dashboard
def get_tenant_link(tenant_name, tenant_id, dashboard_base_url):
	full_url = dashboard_base_url + '/tenant/' + tenant_id + '/dashboard'
	html_code = f'<a href={full_url}>{tenant_name}</a>'
	return html_code

#converts list of events into an list of (up to) 10 tuples which shows the most common files
#in descending order as determined by event count based on md5 along with the most common 
#fully-qualified name, the sha265, and the number of unique hostnames for each
def get_top_10_md5_with_filenames_and_sha256(events):
	md5_counts = {}
	md5_to_filenames = {}
	md5_to_sha256 = {}
	md5_to_hostnames = {}

	# Count the frequency of each MD5 and track filenames, sha256, and hostnames for each MD5
	for event in events:
		md5 = event.get('md5')
		filename = event.get('filename')
		sha256 = event.get('sha256')
		hostname = event.get('hostname')

		if md5:
			md5_counts[md5] = md5_counts.get(md5, 0) + 1

			if filename:
				if md5 not in md5_to_filenames:
					md5_to_filenames[md5] = {}
				md5_to_filenames[md5][filename] = md5_to_filenames[md5].get(filename, 0) + 1

			if sha256:
				if md5 not in md5_to_sha256:
					md5_to_sha256[md5] = {}
				md5_to_sha256[md5][sha256] = md5_to_sha256[md5].get(sha256, 0) + 1

			if hostname:
				if md5 not in md5_to_hostnames:
					md5_to_hostnames[md5] = set()
				md5_to_hostnames[md5].add(hostname)

	# Sort MD5 values by frequency and get the top 10
	sorted_md5 = sorted(md5_counts.items(), key=lambda x: x[1], reverse=True)
	top_10_md5 = []

	for md5, count in sorted_md5[:10]:
		# Find the most popular filename for each MD5
		filenames = md5_to_filenames.get(md5, {})
		most_popular_filename = max(filenames, key=filenames.get, default=None)

		# Find the most popular sha256 for each MD5
		sha256s = md5_to_sha256.get(md5, {})
		most_popular_sha256 = max(sha256s, key=sha256s.get, default=None)

		# Count the number of unique hostnames for each MD5
		unique_hostnames_count = len(md5_to_hostnames.get(md5, set()))	

		top_10_md5.append([md5, count, most_popular_filename, most_popular_sha256, unique_hostnames_count])

	return top_10_md5

#converts list of tuples for the most common files in a tenant into an HTML table including clickable VT links
def convert_to_html_table(top_10_md5, dashboard_base_url, tenant_id):

	# Start the HTML table with headers
	html = '<table border="1"><tr>'
	html += '<th><b>MD5</b></th>'
	html += '<th><b>Events</b></th>'
	html += '<th><b>Hostnames</b></th>'
	html += '<th><b>File Path</b></th>'
	html += '<th><b>More Info</b></th>'
	html += '</tr>'

	# Add rows for each tuple in the top_10_md5 list
	for md5, event_count, filename, sha256, hostnames_count in top_10_md5:
		html += '<tr>'
		html += f'<td>{md5}</td>'
		html += f'<td>{event_count}</td>'
		html += f'<td>{hostnames_count}</td>'
		html += f'<td>{filename}</td>'
		html += f'<td>{get_vt_link(md5)} | {get_repo_link(tenant_id, dashboard_base_url, sha256)}</td>'
		html += '</tr>'
	
	# Close the table tag
	html += '</table>'

	return html

#returns current datetime in human-readable format
def now(format='%Y-%m-%d %H:%M UTC'):
	return datetime.datetime.now(datetime.timezone.utc).strftime(format)

#generates html for email body based on collected data
def generate_email_body_html(tenants_data, dashboard_base_url):
	# Initialize the HTML string
	html_content = f'The below is a summary of recent Airlock Cloud events for each of your {len(tenants_data)} tenants.'

	# Iterate through each tenant's data
	for tenant in tenants_data:
		tenant_name = tenant['tenant_name']
		tenant_id = tenant['tenant_id']
		event_count = tenant['event_count']
		event_summary = tenant['event_summary']

		# Convert the event summary to an HTML table
		event_table_html = convert_to_html_table(event_summary, dashboard_base_url, tenant_id)

		# Convert the tenant id to a clickable link
		tenant_link = get_tenant_link(tenant_name, tenant_id, dashboard_base_url)

		# Add the tenant-specific information to the HTML content
		html_content += f"""
		<p>{tenant_link} had <strong>{event_count}</strong> events between {tenant['datetime_start']} and {tenant['datetime_end']}.
		"""

		# If one or more events occured, add details
		if event_count > 0:
			html_content += f"""
			 The most common files generating events in this tenant were:
			{event_table_html}
			"""
		
		html_content += f"""
			</p>
			"""
		
	return html_content

#sends e-mail via sendgrid with collected data
def send_mail(collected_data, mail_config):

	sg = sendgrid.SendGridAPIClient(api_key=mail_config['sendgrid_api_key'])
	mail_subject = mail_config['mail_subject'] + ' ' + now()
	mail_from = mail_config['from_email']
	dashboard_base_url = mail_config['dashboard_base_url']
	mail_html_body = generate_email_body_html(collected_data, dashboard_base_url)
	
	for recipient in mail_config['to_emails']:	
		
		data = {
			'personalizations': [
				{
				'to': [
					{
						'email': recipient
					}
				],
				'subject': mail_subject
				}
			],
			'from': {
				'email': mail_from
			},
			'content': [
				{
					'type': 'text/html',
					'value': mail_html_body
				}
			]
		}
		response = sg.client.mail.send.post(request_body=data)


# -- DEFINE THE MAIN METHOD USED AT RUNTIME --
def main():
	
	#read configuraiton from JSON on disk
	if debug_mode: print('Attempting to read configuration file', config_file_name)
	config = read_config()
	if debug_mode: print('Value of config is now:\n', json.dumps(config, indent=4))

	#establish a list to store collected data
	collected_data = []

	#iterate through the tenant list
	if debug_mode: print('Beginning to iterate through the tenant list and collect data')
	for tenant in config['tenants']:
		if debug_mode: print('Processing tenant', tenant)

		#if this is new tenant added to config file, add baseline configuration for it
		if 'checkpoint' not in tenant.keys():
			tenant['checkpoint'] = '000000000000000000000000'
		if 'previous_iteration_datetime' not in tenant.keys():
			tenant['previous_iteration_datetime'] = 'the creation of the tenant'

		#get event data for this tenant
		if debug_mode: print('Calling get_events')
		exechistory = get_events(config['server_name'], 
					config['api_key'], 
					config['event_types'], 
					tenant['directoryid'], 
					tenant['Tenantid'], 
					tenant['checkpoint']
					)
		if debug_mode: print('The get_events method returned', len(exechistory), 'rows of data for this tenant')

		#create dictionary with a summary of data collected for this tenant
		if debug_mode: print('Building this_tenant_data')
		this_tenant_data = {	'tenant_name': tenant['name'],
					'tenant_id': tenant['Tenantid'],
					'datetime_start': tenant['previous_iteration_datetime'],
					'datetime_end': now(),
					'event_count': len(exechistory),
					'event_summary': get_top_10_md5_with_filenames_and_sha256(exechistory)				
					}
		if debug_mode: print('This is the data for this tenant:\n', json.dumps(this_tenant_data, indent=4))

		#if we found one or more rows of data, increment the checkpoint on the tenant
		if len(exechistory) > 0:
			tenant['checkpoint'] = exechistory[len(exechistory)-1]['checkpoint']

		#save the ending datetime for reporting next time this script runs
		tenant['previous_iteration_datetime'] = this_tenant_data['datetime_end']

		#append the summary of data for this tenant to the collected data list
		collected_data.append(this_tenant_data)
	if debug_mode: print('Done iterating through the tenant list and collecting data')

	if debug_mode: print('\nThis is the collected data which will be used for generating emails:\n', json.dumps(collected_data, indent=4))

	#send emails with collected data
	if debug_mode: print('\nAttempting to send e-mail(s) using this configuration:\n', config['email'])
	send_mail(collected_data, config['email'])

	#write configuration
	if debug_mode: print('Atempting to write the configuration shown below to disk as', config_file_name)
	if debug_mode: print(json.dumps(config, indent=4))
	write_config(config)


# -- CODE TO INVOKE main() METHOD WHEN PY FILE IS RUN --
if __name__ == "__main__":
	main()
