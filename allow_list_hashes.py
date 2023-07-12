# Example of how to allow list hashes that have not yet been seen on any
# computer with an enforcement, app capture, or baseline builder agent
# on them and therefore are not yet in the file repository.
# 
# Use this command to install prerequisites:
#     pip install requests
#


##CONFIGURATION

#define server configuration
fqdn = 'yourservername'
api_key = 'yourapikey'

#define the application capture that you want to add the hashes to
#note: to get this from GUI, right-click an application capture and
#      choose 'export xml packge', then open resulting file and copy
#      the string between <Timestamp> and </Timestamp>
applicationid = '0000000000'

#define the list of hashes you want to allow list
hash_list = (
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
)

#set ssl mode
verify_ssl = False  #change to True for production
if verify_ssl == False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    
##RUNTIME

#import third-party libearies
import requests
import json
import sys

#calculate base configuration used for requests to server
base_url = f'https://{fqdn}:3129/'
headers = {'X-APIKey': api_key}

#iterate through the hashes
counter = 1
for hash in hash_list:
    
    print('Processing hash', counter, 'of', len(hash_list), hash)

    #add hash to file repository
    request_url = f'{base_url}v1/hash/add'
    payload = {'hashes': [
        {'sha256': hash, 
         'path': f'z:\\none\\{hash}' #make a fake/placeholder path
        }
    ]} 
    response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
    if response.status_code != 200:
        print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload, 'and verify ssl', verify_ssl)
        sys.exit(0)
    else:
        print('Repository entry was successfully created using payload', payload)
    
    #add hash to application capture
    request_url = f'{base_url}v1/hash/application/add'
    payload = {'applicationid': applicationid,
               'hashes': [hash] }    
    response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
    if response.status_code != 200:
        print('ERROR: Unexpected return code', response.status_code, 'on HTTP POST', request_url, 'with headers', headers, 'and payload', payload, 'and verify ssl', verify_ssl)
        sys.exit(0)
    else:
        print('Successfully added', payload['hashes'], 'to application capture', payload['applicationid'])
    
    #increment the counter used for printing to console
    counter += 1
