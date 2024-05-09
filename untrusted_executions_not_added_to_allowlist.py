# Example of how to use /logging/exechistories to get events then query the unique hashes from those
# events using /hash/query and work out which have not been added to any allowlist (formerly application).
# As written, this example has no logic to determine if the allowlist(s) containing the hashes have been added
# to the relevant policy(s) (or any policy at all) and also has no logic to example publisher approvals,
# path exclusions, trusted [grand]parent processes, and allowlist metadata rules.

# set config parameters here
airlock_server = 'foo.ci.managedwhitelisting.com'
api_key = 'bar'

# import required libraries
import requests
import json
import urllib3

# suppress ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# calculate base config based on provided config parameters
base_url = 'https://' + airlock_server + ':3129/v1/'
auth_header = {'X-ApiKey': api_key}

# define search parameters for events
event_search_parameters = {
        # Provide a list of the types of events to get from server using the numerical values below.
        # 0 = "Trusted Execution", 1 = "Blocked Execution", 2 = "Untrusted Execution [Audit]", 
        # 3 = "Untrusted Execution [OTP]", 4 = "Trusted Path Execution", 5 = "Trusted Publisher Execution", 
        # 6 = "Blocklist Execution", 7 = "Blocklist Execution [Audit]", 8 = "Trusted Process Execution"
        'type': [2],
    
        # Retrieve the next event(s) after the specified checkpoint, up to 10K at a time.
        # You can use tooling such as https://steveridout.com/mongo-object-time/ to calculate a checkpoint \
        # for a specific date and time, or use 000000000000000000000000 to get all events in database.
        'checkpoint': '000000000000000000000000', 

        #(Optional) Provide an array of policy group names to retrieve events from the specified policy groups. Not specifying this parameter will return events from all groups.
        #'policy': ['Apple Mac', 'Servers London'] 
        }

#establish a list to store hashes identified as not being in any allowlist
collected_sha256_list_not_in_any_allowlist = []

# enter a while loop, where we will get events and process then in batches of (up to) 10000
while True:
    print('\nQuerying server for events with checkpoint >', event_search_parameters['checkpoint'], '.')
    response = requests.post(base_url + 'logging/exechistories', headers=auth_header, json=event_search_parameters, verify=False)
    exechistories = response.json()['response']['exechistories']
    print('Found', len(exechistories), 'events.')
    
    # calculate list of unique hashes in this set of events
    sha256_list_from_events = []
    for event in exechistories:
        if event['sha256'] not in sha256_list_from_events:
            sha256_list_from_events.append(event['sha256'])
    print('Found', len(sha256_list_from_events), 'unique sha256 values in this set of events.')
        
    # query server for information on the list of hashes
    response = requests.post(base_url + 'hash/query', headers=auth_header, json={'hashes': sha256_list_from_events}, verify=False)
    hash_query_results = response.json()['response']['results']
    
    # parse query results and build a list of files that have not been added to an allowlist
    sha256_list_not_in_any_allowlist = []
    for result in hash_query_results:
        if 'data' not in result.keys():
            sha256_list_not_in_any_allowlist.append(result['sha256'])
        elif 'applications' not in result['data'].keys():
            sha256_list_not_in_any_allowlist.append(result['sha256'])
        elif result['data']['applications'] is None:
            sha256_list_not_in_any_allowlist.append(result['sha256'])
            
    print('Found', len(sha256_list_not_in_any_allowlist), 'sha256 values from this set of that have not been added to any Allowlist (formerly known as Application).')

    # add the newly-found hashes into the master list
    for hash in sha256_list_not_in_any_allowlist:
        if hash not in collected_sha256_list_not_in_any_allowlist:
            collected_sha256_list_not_in_any_allowlist.append(hash)
    print('So far we have found', len(collected_sha256_list_not_in_any_allowlist), 'total unique hashes that have generated an event but are not in an allowlist.')
        
    if len(exechistories) == 10000:
        new_checkpoint = exechistories[len(exechistories)-1]['checkpoint']
        print('Last query produced 10000 results, meaning there may be more data on server. Going back to ask for next batch using a new checkpoint value of', new_checkpoint, '.')
        event_search_parameters['checkpoint'] = new_checkpoint
    else:
        print('The last query produced less than 10000 results, indicating we have all the data. Exiting the while loop.')
        break
        
print('\nDone collecting and analyzing data. We identified a grand total of', 
      len(collected_sha256_list_not_in_any_allowlist), 
      'hashes that appeared in one or more events matching the provided search parameters',
      'and have not been added to any allowlist.'
     )
        
#write the list to a text file on disk
file_name = 'untrusted_execution_sha256_not_added_to_any_allowlist.txt'
print('\nWriting results to disk as', file_name)
with open(file_name, 'w') as file:
    for hash_str in collected_sha256_list_not_in_any_allowlist:
        file.write(hash_str + '\n')
print('The list of', len(collected_sha256_list_not_in_any_allowlist), 'hashes was written to disk as', file_name)