# Description:
# Example of how to bulk import path exclusions


#TODO: Set config here
server_fqdn = 'SERVER-NAME-GOES-HERE'
server_port = 3129
api_key = 'API-KEY-GOES-HERE'
input_file_name = 'paths.txt' #plain text file with one path per line
verify_ssl = True


#required third-party libraries (use 'pip install libraryname' to install)
import requests, json, pandas, sys


#global variables
base_url = ''
headers = {}


#main method
def main():

    #if ssl verification is disabled (typical for lab use), suppress warnings
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #calculate base URL used for request to server
    global base_url
    base_url = 'https://' + server_fqdn + ':' + str(server_port) + '/'

    #calculate headers used for request to server
    global headers
    headers['X-APIKey'] = api_key

    #read list of paths from disk
    paths = pandas.read_csv(input_file_name, header=None)[0].tolist()

    #print list of paths and ask for confirmation
    print('This is the list of the', len(paths), 'paths imported from', input_file_name, 'that will be bulk added:')
    for path in paths:
        print(path)
    user_response = input('Type YES to proceed or any other text to abort: ')
    if user_response.lower() != 'yes':
        print('WARNING: Terminating script based on user response', user_response)
        sys.exit(0)

    #get groups from server
    groups = get_groups()

    #iterate through groups
    for group in groups:
        user_response = input('\nAdd paths to group ' + group['name'] + '? Enter YES to proceed or any other text to skip this group: ')
        if user_response.lower() == 'yes':
            #iterate through list of paths and add each to the group
            for string in paths:
              #add the path to the group
              add_path_exclusion_to_group(group['groupid'], string)
        else:
            print('No paths were added to group', group['name'], group['groupid'], 'based on user response', user_response)


#method which gets all groups from the configured server
def get_groups():
    request_url = f'{base_url}v1/group'
    response = requests.post(request_url, headers=headers, verify=verify_ssl)
    if response.status_code != 200:
        print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url, 'with headers', headers)
        sys.exit(0)
    else:
        groups = response.json()['response']['groups']
        print('INFO: Found', len(groups), 'groups')
        return groups


#method which adds a path to one group
def add_path_exclusion_to_group(group_id, path):
    request_url = f'{base_url}v1/group/path/add'
    payload = {'groupid': group_id, 'path': path}
    response = requests.post(request_url, headers=headers, json=payload, verify=verify_ssl)
    if response.status_code != 200:
        print('ERROR: Unexpected return code', response.status_code, 'on POST to', request_url, 'with headers', headers, 'and payload', payload)
        sys.exit(0)
    else:
        print('INFO: Successfully added', payload['path'], 'to group', payload['groupid'])



#invoke main method when running this script with 'python file_name.py'
if __name__ == "__main__":
    main()
