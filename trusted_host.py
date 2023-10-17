# Example of how to orchestrate automatic allowlisting based on activity
# from from one or more enforcement agents in your environment which
# you declare to be "trusted hosts". 
# 
# As written, this script is intended to let run indefinitely. It will
# poll the Airlock server at an interval you define looking for new
# events matching criteria you define, and then add the associated files
# to the application that you define.
#
# Note that this script is designed to only pick up new executions after
# you launch it, so to use you should follow this workflow
# 1. Configure the script
# 2. Launch the script and leave it running
# 3. Execute the files on the trusted host(s) while the script is running
#
# 
# Use this command to install prerequisites:
#	 pip install requests datetime time
#

##CONFIGURATION

#define server configuration
servername = 'your-server-name'
headers = {'X-APIKey': 'your-api-key'}

#define the application that you want to add the hashes to
#note: to get this from GUI, right-click an application and
#	  choose 'export xml packge', then open resulting file and copy
#	  the string between <Timestamp> and </Timestamp>
applicationid = '0000000000'

#define policy(s) containing the Trusted Host(s)
policies = ['Trusted Hosts']

#define the type (or types) of events to trigger adding files to the application when observed on trusted host
# 0 = Trusted Execution
# 1 = Blocked Execution
# 2 = Untrusted Execution [Audit]
# 3 = Untrusted Execution [OTP]
# 4 = Trusted Path Execution
# 5 = Trusted Publisher Execution
# 6 = Blocklist Execution
# 7 = Blocklist Execution [Audit]
# 8 = Trusted Process Execution
event_types = [1, 2, 3]

#define interval to poll server for new events
sleep_time_in_seconds = 300


##RUNTIME

#import third-party libraries
import requests
import json
import datetime
import time

#suppress ssl warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

#seed initial checkpoint (high water mark) value
response = requests.post(f'https://{servername}:3129/v1/logging/exechistories', headers=headers, json={}, verify=False)
checkpoint = response.json()['response']['exechistories'][0]['checkpoint']

#run in an infinite loop
while True:
	#get new events
	request_url = f'https://{servername}:3129/v1/logging/exechistories'
	payload = {'type': event_types, 
			   'policy': policies,
			   'checkpoint': checkpoint }
	print(datetime.datetime.now().strftime('%H:%M:%S'), 'Querying server for events matching filters', payload)
	response = requests.post(request_url, headers=headers, json=payload, verify=False)  
	exechistories = response.json()['response']['exechistories']
	print(datetime.datetime.now().strftime('%H:%M:%S'), 'Found', len(exechistories), 'new events')

	#if new events were found, process them
	if len(exechistories) > 0:
		
		#build list of unique hashes
		sha256_list = []
		for event in exechistories:
			if event['sha256'] not in sha256_list:
				sha256_list.append(event['sha256'])
		print(datetime.datetime.now().strftime('%H:%M:%S'), 'Found', len(sha256_list), 'unique files:', sha256_list)
		
		#add hashes to configured application
		request_url = f'https://{servername}:3129/v1/hash/application/add'
		payload = {'applicationid': applicationid,
				   'hashes': sha256_list }
		print(datetime.datetime.now().strftime('%H:%M:%S'), 'Sending request to', request_url, 'with payload', payload)		
		response = requests.post(request_url, headers=headers, json=payload, verify=False)
		if response.status_code == 200:
			print(datetime.datetime.now().strftime('%H:%M:%S'), 'Successfully added', len(payload['hashes']), 'files to application capture', payload['applicationid'])
		else:
			print(datetime.datetime.now().strftime('%H:%M:%S'), 'ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
		
		#increment the checkpoint
		checkpoint = exechistories[len(exechistories)-1]['checkpoint']
		print(datetime.datetime.now().strftime('%H:%M:%S'), 'Checkpoint is now', checkpoint)
	
	#sleep for defined interval before repeating loop
	print(datetime.datetime.now().strftime('%H:%M:%S'), 'Sleeping for', sleep_time_in_seconds, 'seconds')
	time.sleep(sleep_time_in_seconds)