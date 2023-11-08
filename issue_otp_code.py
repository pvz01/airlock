# Example of how to programatically retrieve OTP codes based on a hostname
# 
# Use this command to install prerequisites:
#	  pip install requests


##CONFIGURATION

# Set list of OTP durations. This should match the durations enabled in policy.
valid_durations = ['15m', '1h', '6h', '24h', '7d']

# Optionally set server name and/or API key. If left blank, you will be prompted.
server_fqdn = ''
api_key = ''


##RUNTIME

#import required libraries
import requests
import json
import sys

#suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#prompt user for server configuration at runtime if it is not already provided
if server_fqdn == '':
    server_fqdn = input('Server: ')
if api_key == '':
    api_key = input('API Key: ')

#prompt user for hostname
hostname = input('Hostname of the computer to generate an OTP code for: ')

#calculate base URL and headers used for interacting with server
base_url = f'https://{server_fqdn}:3129/v1/'
request_headers = {'X-APIKey': api_key}

#find the agentid for the provided hostname
request_url = base_url + 'agent/find'
request_body = {'hostname': hostname}
print('Querying server for agents with hostname', hostname)
response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
agents = response.json()['response']['agents']
if agents is None:
    agents = []
if len(agents) != 1:
    print('ERROR: Found', len(agents), 'results. Expected quantity is 1. Exiting script.')
    sys.exit(0)
agentid = agents[0]['agentid']
print('Found 1 result with agentid', agentid)

#prompt for purpose
purpose = input('Enter purpose of the OTP code: ')

#prompt for duration
print(valid_durations)
duration = ''
while duration not in valid_durations:
    duration = input('OTP duration (must be one of those lised above): ')

#retrieve OTP code
request_url = base_url + 'otp/retrieve'
request_body = {'duration': duration,
                'agentid': agentid,
                'purpose': purpose}
print('Sending request to server at', request_url, 'with payload', request_body)
response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
otpcode = response.json()['response']['otpcode']
print('OTP Code is', otpcode)