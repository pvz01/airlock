# Example of how to get OTP usage and activity data for a specified hostname(s)
# and print it. You could extend this to further process the data, for example
# by looking up hashes in a threat reputation service and then use that plus 
# other logic you develop to decide whether to add files to an allowlist, add
# to a blocklist, or flag for further review.
# 
# Use this command to install prerequisites:
#	  pip install requests


##CONFIGURATION

# Server configuration
base_url = 'https://your-server-name:3129/v1/'
headers = {'X-APIKey': 'your-api-key'}

# Hostnames
hostnames = ['hostname01', 'hostname02']


##RUNTIME

#import required libraries
import requests
import json

#suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#find the agentids of the hostnames
agentids = []
url = f'{base_url}agent/find'
for hostname in hostnames:
	payload = {'hostname': hostname}
	print('Querying server for agents with hostname', hostname)
	response = requests.post(url, headers=headers, json=payload, verify=False)
	agents = response.json()['response']['agents']
	print(len(agents), 'results')
	for agent in agents:
		agentid = agent['agentid']
		if agentid not in agentids:
			agentids.append(agent['agentid'])
	print('Found a total of', len(agentids), 'agentids matching hostname list', hostnames)
	print(json.dumps(agentids, indent=4))
	
#get OTP usage data
otps = []
url = f'{base_url}otp/usage'
for agentid in agentids:
	payload = {'clientid': agentid}
	print('Querying server for OTP usages for agentid', agentid)
	response = requests.post(url, headers=headers, verify=False, json=payload)
	otpusages = response.json()['response']['otpusage']
	print(len(otpusages), 'results')
	for otpusage in otpusages:
		otps.append(otpusage)
print('Found a total of', len(otps), 'OTP usages matching agentid list', agentids)
print(json.dumps(otps, indent=4))

#add otp activity data
url = f'{base_url}otp/activities'
for otp in otps:
	otpid = otp['otpid']
	payload = {'otpid': otpid}
	print('Querying server for OTP activity for OTP usage with otpid', otpid)
	response = requests.post(url, headers=headers, json=payload, verify=False)
	otpactivities = response.json()['response']['otpactivities']
	print(len(otpactivities), 'results')
	otp['otpactivities'] = otpactivities
	
#print collected data
print('\nDone collecting data. Results:')
print(json.dumps(otps, indent=4))