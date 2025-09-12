## Example of how to ingest a CSV file exported from an IOC in Crowdstrike
## and import the list of blocked hashes into an Airlock Blocklist
##
## Usage:
## 1. Create a .yaml configuration file using the template below
## 2. Export a Crowdstrike IOC in CSV format
## 3. Place the YAML, the CSV, and this PY in the same directory
## 4. Run this command: python import_cs_ioc_to_ald_blocklist.py

## CONFIG FILE TEMPLATE ## 
'''
server_name: foo
api_key: bar
'''

#import libraries and suppress SSL warnings
import requests, json, yaml, csv

#read a CSV file on disk and return a list of dictionaries
def read_csv_as_dicts(file_path):
    print('Reading CS data from', file_path)
    with open(file_path, mode='r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        data = [row for row in csv_reader]
    print('Read', len(data), 'rows of data')
    return data

#parse data ingested from CS and extract a list of sha256 hashes configured for prevention
def build_sha256_list_from_cs_data(data):
    print('Extracting list of unique sha256 hashes with action set to prevent')
    sha256_list = []
    for row in data:
        file_hash = row['value']
        if row['action'] == 'prevent':
            if row['type'] == 'sha256':
                if file_hash not in sha256_list:
                    sha256_list.append(file_hash)
                    #print('Added', file_hash)
                else:
                    print('Skipped', file_hash, 'due to duplicate')
            else:
                print('Skipped', file_hash, 'due to type', row['type'])
        else:
            print('Skipped', file_hash, 'due to action', row['action'])
    print('Found', len(sha256_list), 'unique hashes:', sha256_list)
    return sha256_list

#get a list of existing blocklists
def get_blocklists(config):
    print('Getting list of blocklists from', config['server_name'])
    request_url = 'https://' + config['server_name'] + ':3129/v1/blocklist'
    request_headers = {'X-ApiKey': config['api_key']}
    #print(request_url)
    response = requests.post(request_url, headers=request_headers)
    #print(response.text)
    blocklists = response.json()['response']['blocklists']
    print('Found', len(blocklists), 'blocklists')
    return blocklists

#add a list of hashes to a blocklist
def add_hashes_to_blocklist(config, hash_list, blocklistid):
    print('Adding', len(hash_list), 'hashes to blocklist', blocklistid)
    request_url = 'https://' + config['server_name'] + ':3129/v1/hash/blocklist/add'
    request_headers = {'X-ApiKey': config['api_key']}
    request_body = {'blocklistid': blocklistid,
                    'hashes': hash_list}
    #print(request_url, request_body)
    response = requests.post(request_url, headers=request_headers, json=request_body)
    #print(response.text)
    print(response.json()['error'])
    
#remove a list of hashes from all allowlists
def remove_from_all_allowlists(config, hash_list):
    request_url = 'https://' + config['server_name'] + ':3129/v1/hash/application/remove/all'
    request_headers = {'X-ApiKey': config['api_key']}
    request_body = {'hashes': hash_list}
    print(request_url, request_body)
    response = requests.post(request_url, headers=request_headers, json=request_body)
    print(response.text)

#read airlock server config from a YAML file
def read_config(file_name):
    with open(file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', file_name, 'for', config['server_name'])
    return config

#prompt user to select a blocklist
def choose_blocklist(blocklists):
    for index, item in enumerate(blocklists):
        print(f'{index+1}: {item["name"]} ({item["blocklistid"]})')
    user_response = input('Which blocklist do you want to add the hashes to? ')
    blocklist = blocklists[int(user_response)-1]
    print('You chose', blocklist)
    return blocklist

#main method
def main():

    #get Airlock Server config
    global config
    config_file_name = 'airlock.yaml'
    config = read_config(config_file_name)
    
    #get data from CS
    cs_data_file_name = input('Enter name of CSV containing data from Crowdstrike: ')
    cs_data = read_csv_as_dicts(cs_data_file_name)
    
    #build hash list
    hash_list = build_sha256_list_from_cs_data(cs_data)
    
    #select a blocklist to add the hashes to
    blocklists = get_blocklists(config)
    blocklist = choose_blocklist(blocklists)
    
    #ask the user if they are sure
    user_response = input('Do you want to proceed with adding hashes to the selected blocklist? Enter YES to continue: ')
    if user_response == 'YES':

        #execute the change by adding the hashes to the blocklist
        add_hashes_to_blocklist(config, hash_list, blocklist['blocklistid'])
    else:
        print('Canceled change due to your response', user_response)

#invoke main method when PY file is run
if __name__ == "__main__":
    main()