# Example showing how to clean up unwanted data in existing app captures, using the 
# example of "remove everything with a Python extension".
#
# This script inspects all application captures on the server, identifies if changes are
# warranted, and if yes prompts for confirmation before making changes.

#import required libraries
import requests
import json
import xml.etree.ElementTree as ET
import hashlib
import sys

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#set the list of file extensions for files that you want to remove
extensions_to_remove = ['.py', '.pyi', '.pyc', '.pyd', '.pyo', '.pyw', '.pyz']

#set the maximum quantity of deletions to send to server in a single operation
chunk_size = 5000

#set True/False whether to prompt for each application before making changes
safety_check = True

#get list of applications
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers)
applications = response.json()['response']['applications']
print('INFO: Found', len(applications), 'applications')

#iterate through the application list
for application in applications:
	print('\nINFO: Processing', application['name'])
	
	#get the application
	request_url = base_url + '/v1/application/export'
	payload = {'applicationid': application['applicationid']}
	response = requests.post(request_url, headers=headers, json=payload)
	xml_content = response.text
	
	print('INFO: Downloaded application from server. Beginning analysis.')
	
	#create lists to store hashes
	sha256_remove = []
	sha256_keep = [] 

	#parse the application xml
	root = ET.fromstring(xml_content)
	results_section = root.find(".//ResultsSection")
	if results_section is not None:
		for result in results_section.findall('fileload'):
			path_element = result.find('path')
			if path_element is not None:
				path = path_element.text
				sha256_element = result.find('sha256')
				if sha256_element is not None:
					sha256_value = sha256_element.text
					#check if the path ends with one of the configured extensions
					if any(path.endswith(extension) for extension in extensions_to_remove):
						if sha256_value not in sha256_remove:
							#hash to be removed has been found, add it to list
							sha256_remove.append(sha256_value)
					else:
						if sha256_value not in sha256_keep:
							#hash to be kept has been found, add it to list
							sha256_keep.append(sha256_value)

	#print summary of application analysis
	print('INFO: Analysis is complete. Found', (len(sha256_remove) + len(sha256_keep)), 'total unique hashes.')
	print('INFO:', len(sha256_remove), 'of those match search criteria', extensions_to_remove, '.')
	print('INFO:', len(sha256_keep), 'of those do not match search criteria.')
	
	#if there is nothing to remove, print message and exit this iteration of for loop
	if len(sha256_remove) == 0:
		print('INFO: Because no matches were found, taking no further action on this application.')
		continue  #go to next application
		
	#if there is nothing to keep, print warning but proceed
	elif len(sha256_keep) == 0:
		print('WARNING: All files match the search criteria. Removal will result in an empty application.')
	
	#if safety_check is enabled, prompt user and if they answer anything except yes then exit this iteration of for loop
	if safety_check:
		user_response = input(f'Do you want to remove {len(sha256_remove)} files from {application["name"]} [YES | NO]? ')
		if user_response.lower() != 'yes':
			continue  #go to next application
	   
	#break the list of removals in to smaller chunks before sending to server
	sha256_remove_list_in_chunks = [sha256_remove[i:i+chunk_size] for i in range(0, len(sha256_remove), chunk_size)]
	print('INFO: Removal will be done in', len(sha256_remove_list_in_chunks), 'batches of no more than', chunk_size, 'hashes each.')
	
	#execute the removal
	for sha256_list in sha256_remove_list_in_chunks:
		print('INFO: Removing', len(sha256_list), 'hashes from', application['name'])
		request_url = base_url + '/v1/hash/application/remove'
		payload = {'applicationid': application['applicationid'],
				   'hashes': sha256_list}
		response = requests.post(request_url, headers=headers, json=payload)
