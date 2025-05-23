# export_otp_usage.py
#
# Example of how to export OTP Usage data to disk in Excel format.
#
# This script is published under the GNU General Public License v3.0 and is intended as a working example 
# of how to interact with the Airlock API. It is not a commercial product and is provided 'as-is' with no 
# support. No warranty, express or implied, is provided, and the use of this script is at your own risk.
# Import required libraries
#
# To install dependencies, run this command:
#    pip install requests pyyaml pandas python-dateutil
#
# Requires an API key with permission to the following API endpoint:
#    otp/usage
#
# The script reads from a YAML configuration file, which you will need to create. 
# To create the YAML, copy the example below and paste it into any text editor, make the
# necessary edits, then save it as airlock.yaml in the same directory as the script.
'''
server_name: foo.bar.managedwhitelisting.com
api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
'''

# Import required libraries
import requests, json, yaml, pandas
from datetime import datetime, timezone
import dateutil.parser

# Define a method to get Airlock Server configuration from a YAML file on disk. 
def read_config(file_name='airlock.yaml'):
    print('Reading Airlock Server configuration from', file_name)
    with open(file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config for server', config['server_name'])
    return config

# Define a method to download OTP Usage data from Airlock Server
def get_otp_usages(statuses=[0, 1, 2, 3]):
    otpusages = []
    for status in statuses:
        print('Getting OTP Usages for status', status)
        response = requests.post(url = 'https://' + config['server_name'] + ':3129/v1/otp/usage', 
                                 headers={'X-ApiKey': config['api_key']},
                                 json={'status': str(status)})
        otpusage = response.json()['response']['otpusage']
        if otpusage is None:
            otpusage = []
        print(len(otpusage), 'records found')
        otpusages += otpusage
    print(len(otpusages), 'total records collected')
    return otpusages

# Define a method to add human-readable status values to a list of OTP Usages
def add_status_description(otpusages):
    status_map = {
                    '0': 'Awaiting',
                    '1': 'Active',
                    '2': 'Enforced',
                    '3': 'Revoked Server Side, Pending Agent Check-In'
                }
    print('Calculating status_description using status_map', status_map)
    for otpusage in otpusages:
        otpusage['status_description'] = status_map.get(otpusage['status'], 'Unknown')
    return otpusages

# Define a method to add a granted_days_ago to a list of OTP Usages
def add_granted_days_ago(otpusages):
    now_utc = datetime.now(timezone.utc)
    print('Adding granted_days_ago by comparing granted datetime to', now_utc)
    for otpusage in otpusages:
        granted_cleaned = otpusage['granted'].replace(' UTC', '')
        granted_datetime = dateutil.parser.parse(granted_cleaned)
        delta = now_utc - granted_datetime
        otpusage['granted_days_ago'] = delta.days
    return otpusages

# Define a method to calculate export filename
def calculate_export_filename(config):
    print('Calculating export filename')
    server_alias = config['server_name'].split('.')[0]
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H.%M')
    file_name = 'airlock_otp_usages_' + server_alias + '_' + timestamp + '.xlsx'
    print(file_name, 'will be used for export')
    return file_name

# Define a method to export a list of OTP usages to an Excel file
def export_to_excel(otpusages_df, file_name):
    print('Exporting', len(otpusages_df), 'records to', file_name)
    otpusages_df.to_excel(file_name, index=False)

# Main method, which gets run when this script is executed directly
def main():

    # Get data
    global config
    config = read_config()
    otpusages = get_otp_usages()

    # Process data
    otpusages = add_status_description(otpusages)
    otpusages = add_granted_days_ago(otpusages)

    # Convert the data to a DataFrame
    otpusages_df = pandas.DataFrame(otpusages)

    # OPTIONAL - Filter the data before exporting
    # As an example, if you uncomment the code below it will filter the DataFrame to
    # keep only OTP Usages granted within the last week
    '''
    print(len(otpusages_df), 'entries before filtering')
    filtered_otpusages_df = otpusages_df[otpusages_df['granted_days_ago'] < 8]
    otpusages_df = filtered_otpusages_df
    print(len(otpusages_df), 'enries remain after filtering')
    '''

    # Calculate export filename
    file_name = calculate_export_filename(config)

    # Export the data
    export_to_excel(otpusages_df, file_name)

    print('Done')

if __name__ == "__main__":
    main()
