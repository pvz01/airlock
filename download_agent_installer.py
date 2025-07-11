# Example of how to download Airlock Enforcement Agent installer for single policy
# group and platform.
#
# This script requires an API key with the following permissions:
#     group
#     agent/download
# 
# The API key must be provided along with the DNS name of your Airlock Server in a
# configuration file named 'airlock.yaml'. Create this with any text editor of your
# choice and save it in the same directory as this script. Use this template:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# 
# To install dependencies, run this command:
#     pip install requests pyyaml

# Import required libraries
import requests, json, yaml

# Read Airlock Server configuration from YAML on disk
config_file_name = 'airlock.yaml'
print('Reading configuration from', config_file_name)
with open(config_file_name, 'r') as file:
    config = yaml.safe_load(file)

# Validate configuration
server_name = config.get('server_name', None)
if not server_name:
    print('Error: server_name is missing in the config file')
    sys.exit(1)
else:
    print('Read server_name', server_name)

api_key = config.get('api_key', None)
if not api_key:
    print('Error: api_key is missing in the config file')
    sys.exit(1)
print(f"Read api_key {'*' * (len(api_key) - 4)}{api_key[-4:]}")

# Calculate base configuration for interacting with Airlock Server
base_url = f"https://{server_name}:3129/v1/"
headers = {'X-ApiKey': api_key}

# Get Policy Groups list
print('Getting list of Policy Groups')
url = base_url + 'group'
response = requests.post(url, headers=headers)
print(url, response)
groups = response.json()['response']['groups']
print(len(groups), 'Policy Groups downloaded from server')

# Prompt for group selection
for index, item in enumerate(groups):
    print(f'{index+1}: {item["name"]}')
index = int(input('Which policy group do you want to downlaod the installer for? '))-1
group = groups[index]
groupid = group['groupid']
print('You chose', f"'{group['name']}'", 'which has groupid', groupid)

# Prompt for platform selection
platforms = {
    0: 'Windows',
    1: 'Linux RPM',
    2: 'Linux DEB',
    3: 'macOS'
}
for key, value in platforms.items():
    print(f'{key}: {value}')
platform = int(input('Which OS do you want to download the installer for? '))
print('You chose', platform, platforms[platform])

# Get installer from server
print('Getting the installer from the server')
url = base_url + 'agent/download' + '?groupid=' + groupid + '&platform=' + str(platform)
response = requests.post(url, headers=headers, stream=True)
print(url, response)

# Extract installer filename from Content-Disposition response header
print('Extracting filename from response header')
disposition = response.headers.get("Content-Disposition", "")
filename = disposition.split("filename=", 1)[1].strip('";')
print('Filename provided is', filename)

# Write installer file to disk
print('Writing file to disk')
with open(filename, 'wb') as f:
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            f.write(chunk)
print('Downloaded file was written to', filename)