# Example showing how to end-to-end how to accomplish the following using Airlock REST API
# 1. Add a repository entry for a random hash (useful for testing only)
# 2. Iterate app capture categories, pick one, and add a new app capture within it
# 3. Add hash from step 1 to the new app capture
# 4. Iterate list of policy groups
# 5. Approve app capture form step 3 in all of the parent groups

import requests, json, hashlib, os, random
verify_ssl = True

#uncomment code block below to suppress ssl warnings in lab environment
"""
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
verify_ssl = False
"""

#define Airlock server config
base_url = 'https://fqdn-of-server:3129'
headers = {'X-APIKey': 'api-key-here'}

#add a randomly-generated hash to the file repository (for demo/testing purposes)
random_hash = hashlib.sha256(os.urandom(16)).hexdigest()
print('random_hash is', random_hash)
fake_path = f'z:\\demo\\{random_hash}.fake'
print('fake_path is', fake_path)
request_url = base_url + '/v1/hash/add'
payload = {'hashes':  [
                {'sha256': random_hash,
                 'path': fake_path}
            ]
          }
response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
print(response.status_code, request_url)

#get a listing of app capture categories
request_url = base_url + '/v1/application/categories'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
app_categories = response.json()

#pick an app capture category, in this example just pick the first one
category_id = app_categories['response']['categories'][0]['categoryid']
print('category_id is', category_id)

#create a new application capture
application_name = 'Sample Application ' + str(random.randint(10000000, 99999999))
print('application_name is', application_name)
request_url = base_url + '/v1/application/new'
payload = {'name': application_name,
          'version': '1.0',
          'categoryid': category_id
          }
response = requests.post(request_url, json=payload, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
app_capture_id = response.json()['response']['applicationid']
print('app_capture_id is', app_capture_id)

#add hash to newly-created application capture
request_url = base_url + '/v1/hash/application/add'
payload = {'applicationid': app_capture_id,
           'hashes': [random_hash]
          }
response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
print(response.status_code, request_url)

#get a list of groups (policies)
request_url = base_url + '/v1/group'
response = requests.post(request_url, headers=headers, verify=verify_ssl)
print(response.status_code, request_url)
groups = response.json()['response']['groups']

#approve the newly-created application to all parent policy groups while skipping the child groups
for group in groups:
    if group['parent'] == 'global-policy-settings':
        print('Approving new appplication capture', application_name, 'in group', group['name'], group['groupid'])
        request_url = base_url + '/v1/group/application/approve'
        payload = {'groupid': group['groupid'],
                   'applicationid': app_capture_id}
        response = requests.post(request_url, json=payload, headers=headers, verify=verify_ssl)
        print(response.status_code, request_url)
    else:
        print('Skipping group', group['name'], 'because it is a child of', group['parent'], 'and will inherit allowed application from this parent')