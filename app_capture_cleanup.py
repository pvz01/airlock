# Example showing how to clean up unwanted data in existing app captures,
# using the example of "remove everything with a .py extension". Because
# app captures cannot be programatically modified, this script takes the
# approach of creating a new app capture with the filtered data and then
# finding all of the groups where the original (unmodified) app capture
# was approved and swapping out the old for the new (modified) in these
# groups.
#
# To accomplish the goal, this script does the following:
#
# 1. Iterate app capture categories and look for one with a specific name which
#    needs to be first created in the GUI
# 2. Collects list of groups and their associated approved applications
# 3. Collects a list of application captures
# 4. Inspects each application capture looking for .py files, and two lists
#    of all unique sha256 hashes for Python and non-Python files in that app capture
# 5. If the app capture was all Python files, goes and finds the policies where it's
#    approved and removes that approval.
# 6. If the app capture was all non-Python files, takes no action on policy since no
#    change is required.
# 7. If the app capture was a mix of Python and non-Python files, makes a new app capture
#    with just the non-Python files, then goes and finds the relevant policies where
#    the original unmodified app capture was approved. For each one found it approves
#    the new modified app capture and then unapproves the old app capture.

import requests
import json
import xml.etree.ElementTree as ET
import hashlib
import sys

#uncomment code block below to suppress ssl warnings in lab environment
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
verify_ssl = False
"""

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#get list of app capture categories
request_url = base_url + '/v1/application/categories'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
categories = response.json()['response']['categories']

#find the top-level app category called 'no_py' which will be used for newly-created app captures
categoryid = None
#print(categories)
for category in categories:
    if category['name'] == 'no_py':
        categoryid = category['categoryid']
if categoryid == None:
    print('Please create a top-level app capture category called ''no_py'' and then run script again')
    sys.exit(0)
    
#get a list of groups (policies)
request_url = base_url + '/v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
groups = response.json()['response']['groups']
print(groups)

#add approved application list to each item in the group list
for group in groups:

    #get the policies for this group
    request_url = base_url + '/v1/group/policies'
    payload = {'groupid': group['groupid']}
    response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
    print(response.status_code, request_url)
        
    #build a list of application ids enabled for this policy
    group['applicationids'] = []
    for application in response.json()['response']['applications']:
        group['applicationids'].append(application['applicationid'])   
    
#get list of appplications
request_url = base_url + '/v1/application'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
applications = response.json()['response']['applications']
print('Found', len(applications), 'applications')

#iterate through the existing applications
for application in applications:
    print('Processing', application['name'])
    
    #get existing application from server
    request_url = base_url + '/v1/application/export'
    payload = {'applicationid': application['applicationid']}
    response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
    print(response.status_code, request_url)
    xml_content = response.text    
    
    #parse the XML content, and generate lists of sha256 for python and non-python files
    sha256_non_python = []
    sha256_python = []

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
                    if path.endswith('.py'):
                        if sha256_value not in sha256_python:
                            sha256_python.append(sha256_value)
                    else:
                        if sha256_value not in  sha256_non_python:
                            sha256_non_python.append(sha256_value)

    print('found', len(sha256_non_python), 'unique SHA-256 values for non-Python files')
    print('found', len(sha256_python), 'unique SHA-256 values for Python files')

    if len(sha256_python) == 0:
        print('Since there were no Python files found in app capture, taking no further action.')
    elif len(sha256_non_python) == 0:
        print('After removing the Python files, nothing remains. Finding matching policies to disable this app capture.')
            
        for group in groups:
            if application['applicationid'] in group['applicationids']:
                print('Found', application['applicationid'], 'to be on the list of applicationids in', group['name'])
                
                #remove the app capture from this group
                print('Removing', application['name'], 'from group', group['name'])
                request_url = base_url + '/v1/group/application/deny'
                payload = {'applicationid': application['applicationid'],
                           'groupid': group['groupid'] }
                response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
                print(response.status_code, request_url)
        
        
    else:
        
        #make a new app capture
        application_name = application['name'] + '_no_py'
        request_url = base_url + '/v1/application/new'
        payload = {'name': application_name,
                   'version': '0',
                   'categoryid': categoryid
                  }
        response = requests.post(request_url, json=payload, headers=headers, verify=verify_ssl)
        print(response.status_code, request_url)
        new_app_capture = response.json()['response']
        print(new_app_capture)
        
        #add non-python hashes to the new app capture
        request_url = base_url + '/v1/hash/application/add'
        payload = {'applicationid': new_app_capture['applicationid'],
                   'hashes': sha256_non_python
                  }
        response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
        print(response.status_code, request_url)
        
        #iterate through groups, enable new app capture in policy and disable the old wherever the old was approved
        for group in groups:
            
            if application['applicationid'] in group['applicationids']:
             
                print('Found', application['applicationid'], 'to be on the list of applicationids in', group['name'])
                
                #add the new app capture to this group
                print('Adding', application_name, 'to group', group['name'])
                request_url = base_url + '/v1/group/application/approve'
                payload = {'applicationid': new_app_capture['applicationid'],
                           'groupid': group['groupid'] }                
                response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
                print(response.status_code, request_url)
                
                #remove the old app capture
                print('Removing', application['name'], 'from group', group['name'])
                request_url = base_url + '/v1/group/application/deny'
                payload = {'applicationid': application['applicationid'],
                           'groupid': group['groupid'] }
                response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
                print(response.status_code, request_url)
            
            else:
                print('Application', application, 'is not on list of approved applications in', group['name'], 'and therefore no policy modifaction is required.')