# summarize_events.py
# Version: 1.0
# Last updated: 2024-08-23
# Patrick Van Zandt <patrick@airlockdigital.com>, Principal Customer Success Manager

import requests, json, urllib3, datetime, time, yaml, re, os, pandas, datetime, bson
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_config(file_name):
    with open(file_name, 'r') as file:
        config = yaml.safe_load(file)
    print('Read config from', file_name, 'for server', config['server_name'])
    return config

def objectid_n_days_ago(n):
    datetime_n_days_ago = datetime.datetime.now() - datetime.timedelta(days=n)
    print('Calculating objectid for', datetime_n_days_ago)
    timestamp = int(datetime_n_days_ago.timestamp())
    objectid_hex = hex(timestamp)[2:] + '0000000000000000'
    return bson.ObjectId(objectid_hex)

def get_exechistories(server_name, api_key, types=[2], checkpoint='000000000000000000000000'):
    request_url = 'https://' + server_name + ':3129/v1/logging/exechistories'
    request_headers = {'X-APIKey': api_key}
    request_body = {'type': types,
                    'checkpoint': checkpoint}
    
    collected_events = []
    while True:

        #get up to 10K events from server
        response = requests.post(request_url, headers=request_headers, json=request_body, verify=False)
        events = response.json()['response']['exechistories']
        print(request_url, request_body, 'returned', len(events), 'events')

        #append new events to list of collected events
        collected_events += events
        
        #if we got exactly 10K events back, reset checkpoint based on last event returned to use for next iteration
        if len(events) == 10000:
            request_body['checkpoint'] = events[len(events)-1]['checkpoint']

        #any other quantity except 10K means we already have all the events so we can exit the while loop
        else:
            break
    
    return collected_events

def summarize_events(events, output_filename, fields=['sha256', 'full_path', 'path', 'file_name', 'publisher', 'parent_process', 'hostname']):
    print('Analyzing a list of', '{:,}'.format(len(events)), 'events for most common occurences of', fields)

    #load data into a DataFrame
    df = pandas.DataFrame(events)

    #rename columns
    df.rename(columns={'filename': 'full_path'}, inplace=True)
    df.rename(columns={'pprocess': 'parent_process'}, inplace=True)
    
    #sanitize/generalize usernames
    for fieldname in ['full_path', 'parent_process']:
        df[fieldname] = df[fieldname].apply(lambda x: re.sub(r'C:\\users\\[^\\]+', r'C:\\users\\*', x, flags=re.IGNORECASE))

    #split full_path into path and file_name
    def split_full_path(full_path):
        match = re.match(r"^(.*[\\/])?([^\\/]+)$", full_path)
        if match:
            path = match.group(1) if match.group(1) else ""
            file_name = match.group(2)
            return path, file_name
        return "", full_path
    df[['path', 'file_name']] = df['full_path'].apply(lambda x: split_full_path(x)).apply(pandas.Series)
    
    #function to find top 10 values for a given field and return summary including percents
    def get_top_values_with_percent(df, field):
        counts = df[field].value_counts().head(10)
        total = len(df)
        percentages = (counts / total * 100).round(2)
        combined = counts.astype(str) + ' (' + percentages.astype(str) + '%)'
        return pandas.DataFrame({'Value': counts.index, 'Count (Percentage)': combined})
        
    #open the output file
    with open(output_filename, 'w') as file:
        file.write(f'Analyzing a list of {"{:,}".format(len(events))} events for most common occurrences of {fields}\n')

        for field in fields:
            file.write(f'\nTop 10 most common values for {field}:\n')
            top_values = get_top_values_with_percent(df, field)
            
            # calculate the maximum length of the "Value" column to ensure dynamic alignment
            max_value_length = top_values['Value'].str.len().max()

            # manually format the output to ensure left alignment
            for index, row in top_values.iterrows():
                file.write(f"{row['Value']:<{max_value_length}} {row['Count (Percentage)']}\n")
            
    print(f'Summary has been written to {output_filename}')

def main():
    
    readme_message = """
Welcome to the Airlock Event Summarizer tool. This utility downloads events from your Airlock Server,
calculates the most common values for each of a series of fields, and writes the result to disk as
a text file. This can be useful to help understand large data sets often seen during initial installation
when your allowlisting policies are relatively immature (undefined). Specifically, it can help highlight
the files (candidates for trusting by hash), folders (candidates for Path Exclusions), and parent processes
(candidates for trusted processes) that are generating the most traffic in your environment. This tool 
reads server configuration from a YAML configuration file. Use a text editor of your choice to create a 
configuration file matching this syntax:

server_name: foo
api_key: bar

Your API key must have permission to the logging/exechistories API endpoint.
    """

    print(readme_message)
    
    #get config from YAML on disk
    config_file_name = input('Enter the name of a YAML file containing server configuration: ')
    config = read_config(config_file_name)
    server_name = config['server_name']
    api_key = config['api_key']
   
    #calculate timestamps and associated checkpoint (objectid)  
    now = datetime.datetime.utcnow()
    timestamp_to_str = now.strftime('%Y-%m-%d_%H-%M_UTC')
    days = int(input('\nHow many days worth of events do you want to analyze? '))
    datetime_from = now - datetime.timedelta(days=days)
    timestamp_from_str = datetime_from.strftime('%Y-%m-%d_%H-%M_UTC')
    checkpoint = str(objectid_n_days_ago(days))
    
    #get events
    print('Downloading events ranging from', timestamp_from_str, 'to', timestamp_to_str)
    events = get_exechistories(server_name, api_key, checkpoint=checkpoint)
    print('Done collecting events.\n')

    #calculate file name for export    
    output_filename = server_name.split('.')[0] + '_event_summary_' + timestamp_from_str + '_to_' + timestamp_to_str + '.txt'
    print('Summary will be written to', output_filename)

    #summarize events and write output to disk
    summarize_events(events, output_filename, fields=['sha256', 'full_path', 'path', 'file_name', 'publisher', 'parent_process', 'hostname'])

    print('Done')

if __name__ == '__main__':
	main()