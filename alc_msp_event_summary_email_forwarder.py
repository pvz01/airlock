# alc_msp_event_summary_email_forwarder.py
# Version: 2.0
# Last updated: 2024-01-12
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

'''This is an example of how to generate e-mail summaries of event data for n number of
tenants in Airlock Cloud using the Airlock API. Each time this script is run, it will read 
configuration from a YAML file on disk, gather data, generate and send the email, and 
then write updated configuration to disk for usage at the next execution of the script.

Consider using cron, Windows Task Scheduler, or another automation tool to run this
script at a recurring interval such as daily.

In an effort to provide an easy-to-understand working example, I intentionally avoided
introducing error handling or retry mechanisms. This makes the code easier to read but also
makes it fragile. Things like invalid API keys, lack of network access, system resource
limitations (especially for large data sets), or even mis- or under-performing Airlock or
Sendgrid servers will cause failures. You will want to monitor for failures using external 
tooling, or alternately add this withing the script yourself. In the event of a failure, no 
irreparable harm is done in the sense that the config file will not be modified and the same
operations will be automatically retried on the next iteration.

Follow the template below to create the required YAML configuration file before running the
script the first time. Set the location below as a relative or absolute path and filename'''

config_file = 'alc_msp_event_summary_email_forwarder.yaml'

'''
server_name: au.appenforcement.com
api_key: your-airlock-cloud-api-key
tenants:
  - name: Tenant 1
    directory_id: x
    tenant_id: y
  - name: Tenant 2
    directory_id: x
    tenant_id: y
event_types:
  - 0  #Trusted Execution
  - 1  #Blocked Execution
  - 2  #Untrusted Execution [Audit]
  - 3  #Untrusted Execution [OTP]
  - 4  #Trusted Path Execution
  - 5  #Trusted Publisher Execution
  - 6  #Blocklist Execution
  - 7  #Blocklist Execution [Audit]
  - 8  #Trusted Process Execution
email:
  sendgrid_api_key: your-sendgrid-api-key
  mail_subject: Airlock Cloud event summary
  from_email: airlock@airlockdigital.com
  to_emails:
    - user1@domain.com
    - user2@domain.com
  dashboard_base_url: https://portal.au.appenforcement.com
  abbreviate_hashes: True
''' 

# -- IMPORT REQUIRED LIBRARIES --
import requests
import json
import yaml
import datetime
import sendgrid
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #suppress ssl warnings

# -- DEFINE A SERIES OF METHODS USED AT RUNTIME --

# Reads YAML config file from disk and return it as a dictionary
def read_config():
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)  # Uses safe_load to prevent executing arbitrary code
    return config

# Writes config dictionary to disk as YAML file
def write_config(config):
    with open(config_file, 'w') as file:
        yaml.dump(config, file, indent=4, default_flow_style=False)  # Set default_flow_style to False for human-readable style

# Gets new events for a single tenant
def get_events(server_name, api_key, event_types, directoryid, tenantid, checkpoint):
	
	request_url = 'https://' + server_name + '/willard/v1/logging/exechistories'
	request_headers = {
			'UserApiKey': api_key,
			'directoryid': directoryid,
			'tenantID': tenantid,
			}
	request_body = {'type': event_types}

	events = []
	while True:
		request_body['checkpoint'] = checkpoint
		print(now(format='%H:%M:%S'), request_url)
		response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
		print(now(format='%H:%M:%S'), response)
		exechistories = response.json()['response']['exechistories']
		print(now(format='%H:%M:%S'), len(exechistories), 'events returned')
		events += exechistories
		if len(exechistories) < 10000:
			#all available data has been collected, exit the while loop
			break
		else:
			#increment the checkpoint using the value in the last event returned
			checkpoint = exechistories[len(exechistories)-1]['checkpoint']
			print(now(format='%H:%M:%S'), 'Querying for additional events with checkpoint >', checkpoint)
	
	return events

# Creates clickable VirusTotal search link
def create_vt_link(hash):
	base_url = 'https://www.virustotal.com/gui/search/'
	full_url = base_url + hash
	html = f'<a href={full_url}>VT</a>'
	return html

# Creates a clickable Airlock Repository link
def create_repo_link(tenant_id, dashboard_base_url, sha256):
	url = dashboard_base_url + '/tenant/' + tenant_id + '/repository?SHA256=' + sha256
	html = f'<a href={url}>ALD</a>'
	return html

# Creates a clickable Airlock Tenant link
def create_tenant_link(tenant_name, tenant_id, dashboard_base_url):
	url = dashboard_base_url + '/tenant/' + tenant_id + '/dashboard'
	html = f'<a href={url}>{tenant_name}</a>'
	return html

# Summarizes events by most popular 10 hashes plus hostname count and most common filename for each
def top_10_sha256(events):
    sha256_counts = {}
    sha256_to_filenames = {}
    sha256_to_hostnames = {}

    for event in events:
        sha256 = event.get('sha256')
        filename = event.get('filename')
        hostname = event.get('hostname')

        if sha256:
            sha256_counts[sha256] = sha256_counts.get(sha256, 0) + 1

            if filename:
                if sha256 not in sha256_to_filenames:
                    sha256_to_filenames[sha256] = {}
                sha256_to_filenames[sha256][filename] = sha256_to_filenames[sha256].get(filename, 0) + 1

            if hostname:
                if sha256 not in sha256_to_hostnames:
                    sha256_to_hostnames[sha256] = set()
                sha256_to_hostnames[sha256].add(hostname)

    sorted_sha256 = sorted(sha256_counts.items(), key=lambda x: x[1], reverse=True)
    top_10_sha256 = []

    for sha256, count in sorted_sha256[:10]:
        filenames = sha256_to_filenames.get(sha256, {})
        most_popular_filename = max(filenames, key=filenames.get, default=None)

        unique_hostnames_count = len(sha256_to_hostnames.get(sha256, set()))    

        top_10_sha256.append([sha256, count, most_popular_filename, unique_hostnames_count])

    return top_10_sha256

# Creates an HTML table based on event summary for a tenant
def create_event_table(event_summary, dashboard_base_url, tenant_id, abbreviate_hashes):

	html = '<table border="1"><tr>'
	html += '<th><b>SHA-256</b></th>'
	html += '<th><b>Events</b></th>'
	html += '<th><b>Hostnames</b></th>'
	html += '<th><b>File Path (most common)</b></th>'
	html += '<th><b>More</b></th>'
	html += '</tr>'

	for sha256, event_count, filename, hostnames_count in event_summary:
		html += '<tr>'
		if abbreviate_hashes:
			html += f'<td>{sha256[:4] + "..." + sha256[-4:]}</td>' #abbreviate hashes for better display
		else:
			html += f'<td>{sha256}</td>' #use full hashes
		html += f'<td>{event_count}</td>'
		html += f'<td>{hostnames_count}</td>'
		html += f'<td>{filename}</td>'
		html += f'<td>{create_vt_link(sha256)} | {create_repo_link(tenant_id, dashboard_base_url, sha256)}</td>'
		html += '</tr>'
	
	html += '</table>'

	return html

# Returns current datetime in human-readable format
def now(format='%Y-%m-%d %H:%M UTC'):
	return datetime.datetime.now(datetime.timezone.utc).strftime(format)

# Creates HTML code to be used for the body of an e-mail
def generate_email_body_html(tenants_data, dashboard_base_url, abbreviate_hashes):

	html = f'The below is a summary of recent Airlock Cloud events for each of your {len(tenants_data)} tenants.'

	for tenant in tenants_data:	
		tenant_name = tenant['tenant_name']
		tenant_id = tenant['tenant_id']
		event_count = tenant['event_count']
		event_summary = tenant['event_summary']
		tenant_link = create_tenant_link(tenant_name, tenant_id, dashboard_base_url)

		html += f'<p>{tenant_link} had {event_count} events between {tenant["datetime_start"]} and {tenant["datetime_end"]}. '

		if event_count > 0:
			html += 'The most common files generating events in this tenant were:'
			html += f'{create_event_table(event_summary, dashboard_base_url, tenant_id, abbreviate_hashes)}'
		
		html += f'</p>'
		
	return html

# Sends e-mails using Sendgrid
def send_mails_with_sendgrid(collected_data, mail_config):

	sg = sendgrid.SendGridAPIClient(api_key=mail_config['sendgrid_api_key'])
	mail_subject = mail_config['mail_subject'] + ' ' + now()
	mail_from = mail_config['from_email']
	dashboard_base_url = mail_config['dashboard_base_url']
	abbreviate_hashes = mail_config['abbreviate_hashes']
	mail_html_body = generate_email_body_html(collected_data, dashboard_base_url, abbreviate_hashes)
	
	for recipient in mail_config['to_emails']:	
		print(now(format='%H:%M:%S'), recipient)
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
		print(now(format='%H:%M:%S'), response.status_code)

# -- DEFINE THE MAIN METHOD USED AT RUNTIME --
def main():
	
	print(now(format='%H:%M:%S'), 'Reading configuration from', config_file)
	config = read_config()
	
	collected_data = []

	counter = 1
	for tenant in config['tenants']:
		
		print(f"\n{now(format='%H:%M:%S')} Gathering data for tenant {counter} of {len(config['tenants'])}: {tenant['name']}")

		if 'checkpoint' not in tenant.keys():
			tenant['checkpoint'] = '000000000000000000000000' #no checkpoint was provided, so get all events
		if 'previous_iteration_datetime' not in tenant.keys():
			tenant['previous_iteration_datetime'] = '2013-12-23 01:14 UTC' #HAS-1 creation aka ALD inception :-)

		print(now(format='%H:%M:%S'), 'Getting events with checkpoint >', tenant['checkpoint'])
		exechistory = get_events(	config['server_name'], 
									config['api_key'], 
									config['event_types'], 
									tenant['directory_id'], 
									tenant['tenant_id'], 
									tenant['checkpoint']
								)
		print(now(format='%H:%M:%S'), len(exechistory), 'total events for this tenant')

		print(now(format='%H:%M:%S'), 'Analyzing the data for tenant', tenant['name'])
		this_tenant_data = {	'tenant_name': tenant['name'],
								'tenant_id': tenant['tenant_id'],
								'datetime_start': tenant['previous_iteration_datetime'],
								'datetime_end': now(),
								'event_count': len(exechistory),
								'event_summary': top_10_sha256(exechistory)				
					}

		if len(exechistory) > 0:
			print(f"{now(format='%H:%M:%S')} checkpoint incremented from '{tenant['checkpoint']}' to", end=" ")
			tenant['checkpoint'] = exechistory[len(exechistory)-1]['checkpoint']
			print(f"'{tenant['checkpoint']}'")
		else:
			print(f"{now(format='%H:%M:%S')} checkpoint remains unchanged at '{tenant['checkpoint']}'")

		print(f"{now(format='%H:%M:%S')} previous_iteration_datetime incremented from '{tenant['previous_iteration_datetime']}' to", end=" ")
		tenant['previous_iteration_datetime'] = this_tenant_data['datetime_end']
		print(f"'{tenant['previous_iteration_datetime']}'")

		collected_data.append(this_tenant_data)
		print(now(format='%H:%M:%S'), 'Done with tenant', counter, 'of', len(config['tenants']), tenant['name'])
		counter += 1

	print(f"\n{now(format='%H:%M:%S')} Sending e-mails")
	send_mails_with_sendgrid(collected_data, config['email'])

	print(f"\n{now(format='%H:%M:%S')} Writing configuration to {config_file}")
	write_config(config)


# -- INVOKE main() METHOD WHEN PY FILE IS RUN --
if __name__ == "__main__":
	main()