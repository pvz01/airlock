# export_otpusage.py
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager
#
# Example of how to export OTP Usage data to an XLSX, including several derived fields
# useful for downstream analysis with a PivotTable.
#
# This script requires an API key with the following permissions:
#     otp/usage
#
# The API key must be provided along with the DNS name of your Airlock Server in a
# configuration file named 'airlock.yaml'. Create this with any text editor of your
# choice and save it in the same directory as this script. Use this template:
'''
server_name: foo.bar.managedwhitelisting.com
api_key: yourapikey
'''
# To install dependencies, run this command:
#     pip install requests pyyaml pandas

# Import required libraries
import yaml, json, requests, pandas
from datetime import datetime, timezone

# Get Airlock Server config
config_file_name = 'airlock.yaml'
with open(config_file_name, 'r') as file:
    config = yaml.safe_load(file)
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Read config for Airlock Server', config['server_name'], 'from', config_file_name)

# Download OTP Usage records
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Downloading OTP Usage records from Airlock Server')
url = 'https://' + config['server_name'] + ':3129/v1/otp/usage'
headers = {'X-ApiKey': config['api_key']}
collected_otpusage = []
for status in range(0,4):
    body = {'status': str(status)}
    response = requests.post(url, json=body, headers=headers)
    print(datetime.now(timezone.utc).strftime("%H:%M:%S"), url, body, response)
    otpusage = response.json()['response']['otpusage']
    if otpusage is not None:
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), len(otpusage), 'records found')
        collected_otpusage += otpusage
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), len(collected_otpusage), 'collected records')
    else:
        print(datetime.now(timezone.utc).strftime("%H:%M:%S"), '0 records found')
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), len(collected_otpusage), 'total records were downloaded')

# Prepare data for export using Pandas DataFrame
df = pandas.DataFrame(collected_otpusage)
df['granted_date'] = df['granted'].astype(str).str.slice(0, 10)
status_mapping = {0: 'Awaiting', 1: 'Active', 2: 'Enforced', 3: 'Revoked'}
df['status'] = pandas.to_numeric(df['status'], errors='coerce').map(status_mapping)

# Add OTP Session type
def classify_session(row):
    if row['otpcode'] == 'Self Service':
        return 'Self Service'
    elif row['user'] == 'Mobile OTP' and len(row['otpcode']) == 6:
        return 'Mobile'
    else:
        return 'Code'
df['type'] = df.apply(classify_session, axis=1)

# Reorder columns: move granted_date, hostname, user to the front
preferred_first = ['granted_date', 'type', 'hostname', 'user', 'duration', 'status']
remaining = [col for col in df.columns if col not in preferred_first]
df = df[preferred_first + remaining]

# Generate export filename
output_filename = f"{config['server_name'].split('.')[0]}_otpusage_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M_utc')}_{len(collected_otpusage)}.xlsx"
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Exporting data to', output_filename)

# Export to Excel
df.to_excel(output_filename, index=False, sheet_name='otpusage_data')
print(datetime.now(timezone.utc).strftime("%H:%M:%S"), 'Done')