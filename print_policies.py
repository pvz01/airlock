# Example of how to print policy list and configuration to the console
# Note: inherited settings are printed relative to the parent policy group but not the children
# 
# Use this command to install prerequisites:
#     pip install requests

import requests, json, sys, yaml, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#create global variables
base_url = ''
headers = {}
include_additional_settings = False

#define a series of functions used for the analysis

def read_config(config_file_name):
    with open(config_file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', config_file_name, config)
    return config

def get_groups():
	request_url = f'{base_url}v1/group'
	response = requests.post(request_url, headers=headers, verify=False)
	if response.status_code == 200:
		return response.json()['response']['groups']
	else:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers)
		sys.exit(0)

def get_policy_for_group(group):
	request_url = f'{base_url}v1/group/policies'
	payload = {'groupid': group['groupid']}
	response = requests.post(request_url, headers=headers, json=payload, verify=False)
	if response.status_code == 200:
		return response.json()['response']
	else:
		print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload)
		sys.exit(0)

def print_policy(policy):
	
	name = policy.pop('name')
	print(f"\n{name}")
	   
	auditmode = policy.pop('auditmode')
	if auditmode == 1:
		print('This policy is an audit mode policy')
	else:
		print('This policy is an enforcement mode policy')
	
	baselines = policy.pop('baselines')
	if baselines != None:
		print(f"\n{len(baselines)} baselines")
		for baseline in baselines:
			print(f"\t{baseline['name']}")
	
	applications = policy.pop('applications')
	if applications != None:
		print(f"\n{len(applications)} applications")
		for application in applications:
			print(f"\t{application['name']}")
	
	publishers = policy.pop('publishers')
	if publishers != None:
		print(f"\n{len(publishers)} publishers")
		for publisher in publishers:
			print(f"\t{publisher['name']}")
		
	paths = policy.pop('paths')
	if paths != None:
		print(f"\n{len(paths)} paths")
		for path in paths:
			currentpath = path['name']
			currentpath = currentpath.replace('\\\\', '\\') #replace double backslashes with singles
			print(f"\t{currentpath}")
	
	blocklists = policy.pop('blocklists')
	if blocklists != None:
		print(f"\n{len(blocklists)} blocklists")
		for blocklist in blocklists:
			if blocklist['audit'] == 1:
				print(f"\t[AUDIT MODE] {blocklist['name']}")
			else:
				print(f"\t{blocklist['name']}")
			
	if include_additional_settings:
		print(f"\nAdditional settings:")
		print(json.dumps(policy, indent=4))

#main method that is used at runtime
def main():
	global base_url
	global headers
	global include_additional_settings

	#get airlock server config and calculate base configuration for server interaction
	config = read_config('airlock.yaml')
	base_url = 'https://' + config['server_name'] + ':3129/'
	headers = {'X-APIKey': config['api_key']}
	
	#prompt for config
	include_additional_settings = input('Include additional settings? Enter YES or NO, or press return to accept the default (NO): ')
	if include_additional_settings.lower() == 'yes':
		include_additional_settings = True

	#get groups from server	
	groups = get_groups()
	
	#iterate through the groups
	for group in groups:
		#get the policy for this group
		policy = get_policy_for_group(group)
		#print the policy
		print_policy(policy)

#when the file is run (python filename.py), invoke the main() method
if __name__ == "__main__":
	main()