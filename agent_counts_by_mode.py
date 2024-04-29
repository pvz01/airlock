# This example shows how to read the list of agents and associated information
# and organize them into catagory based on agent type and mode. Requires 
# Airlock Server version 5.3.1 or above due to usage of server-side filtering
# of OTP status.
#
# Use this command to install prerequisites:
#	 pip install requests
#
# Generate an API key which has permission to the following endpoints:
#    otp/usage
#    group
#    group/policies
#    agent/find


##CONFIGURATION

#server configuration
server_fqdn = 'FOO.ci.managedwhitelisting.com'
apikey = 'BAR'


##RUNTIME

#import required libraries
import requests
import json
import urllib3

#suppress ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#build headers used for requests to server
headers = {'X-APIKey': apikey}

#get list of active otp sessions
url = 'https://' + server_fqdn + ':3129/v1/otp/usage'
body = {'status': '1'} #get active OTP usages only
response = requests.post(url, headers=headers, json=body, verify=False)
active_otp_usages = response.json()['response']['otpusage']

#build list of agent clientids in OTP mode
clientids_in_otp_mode = []
if active_otp_usages is not None:
    for otpusage in active_otp_usages:
        if otpusage['clientid'] not in clientids_in_otp_mode:
            clientids_in_otp_mode.append(otpusage['clientid'])

#get list of groups
url = 'https://' + server_fqdn + ':3129/v1/group'
body = {}
response = requests.post(url, headers=headers, json=body, verify=False)
groups = response.json()['response']['groups']

#read policy for each group and record auditmode
for group in groups:
    url = 'https://' + server_fqdn + ':3129/v1/group/policies'
    body = {'groupid': group['groupid']}
    response = requests.post(url, headers=headers, json=body, verify=False)
    group['auditmode'] = response.json()['response']['auditmode']

#build list of groupids where enforcement mode is enabled
groupids_in_enforcement_mode = []
for group in groups:
    if group['auditmode'] == 0:
        groupids_in_enforcement_mode.append(group['groupid'])

#get list of agents
url = 'https://' + server_fqdn + ':3129/v1/agent/find'
body = {}
response = requests.post(url, headers=headers, json=body, verify=False)
agents = response.json()['response']['agents']

#define lists to organize agents by category
airlock_enforcement_agents_enforcement_mode = []
airlock_enforcement_agents_audit_mode = []
airlock_enforcement_agents_otp_mode = []
airlock_enforcement_agents_unmanaged = []
airlock_application_capture_agents = []

#organize agents into lists by category
for agent in agents:
    if agent['groupid'] == 'Unmanaged':
        airlock_enforcement_agents_unmanaged.append(agent)
    elif agent['agentid'] in clientids_in_otp_mode:
        airlock_enforcement_agents_otp_mode.append(agent)
    elif agent['groupid'] in groupids_in_enforcement_mode:
        airlock_enforcement_agents_enforcement_mode.append(agent)
    elif agent['groupid'] == 'airlock-application-trust-capture':
        airlock_application_capture_agents.append(agent)
    else:
        airlock_enforcement_agents_audit_mode.append(agent)

#print results
print('On Airlock Server', server_fqdn, 'there are', len(agents), 'total agents')
print(len(airlock_enforcement_agents_enforcement_mode), 'Airlock Enforcement Agents in Enforcement Mode')
print(len(airlock_enforcement_agents_audit_mode), 'Airlock Enforcement Agents in Audit Mode')
print(len(airlock_enforcement_agents_otp_mode), 'Airlock Enforcement Agents in OTP Mode')
print(len(airlock_enforcement_agents_unmanaged), 'Airlock Enforcement Agents that are Unmanaged (disabled)')
print(len(airlock_application_capture_agents), 'Airlock Application Capture Agents')