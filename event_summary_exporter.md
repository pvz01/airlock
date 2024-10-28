# Event Summary Exporter Documentation

## Overview

This script, [event_summary_exporter.py](event_summary_exporter.py) automates the process of analyzing execution history (event) data from an Airlock server for the most common activity patterns and writing summary reports to an easy-to-understand yet structured Excel file. This can be useful during implementation -- when allowlisting policies are naturally less mature and event volume is high -- to identify high-impact candidates to add as Path Exclusions, Trusted Parent Processes, or file (hash) approvals.

### License
This script is published under the GNU General Public License v3.0 and is intended as a practical example of how to interact with the [Airlock Digital REST API](https://api.airlockdigital.com/). It is not a commercial product and is provided 'as-is' with no support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

### Prerequisites
The script requires:
- An API key with `logging/exechistories` permission.
- Python 3.x with the following libraries: `requests`, `pandas`, `yaml`, `openpyxl`, `bson`.

## Functionality

The script performs the following tasks:

1. **Load Configuration**: Reads configuration settings from a YAML file (`airlock.yaml`) to specify server configuration, event filters, and output details.
2. **Download Events**: Retrieves event data from the Airlock server.
4. **Process Data**:
   - Anonymizes usernames in file and process paths.
   - Renames key columns for clarity.
   - Splits fully-qualified filenames into folder and file components.
5. **Analyze Data**: Identifies and counts the top N most common values for each selected field.
6. **Export Results**: Outputs the analyzed data to an Excel file, with column formatting and summary worksheets.

## Configuration File (YAML)

The script reads from a YAML configuration file, which you will need to create. To create the YAML, copy the example below and paste it into any text editor, make the necessary edits, then save it as `airlock.yaml` in the same directory as the script.

### Required Properties - in root of YAML

- **`api_key`**: (string) The API key for authenticating with the Airlock server.
- **`server_name`**: (string) The server's hostname or IP address.

### Optional Properties - in `event_summary_exporter` section of YAML

- **`lookback_hours`**: (integer, default=168) The number of hours to look back for event retrieval. Defaults to one week (168 hours).
- **`event_types`**: (list of integers, default=[2]) Event types to retrieve. Default is `2` (Untrusted Execution [Audit]).
- **`max_event_quantity`**: (integer, default=10,000,000) Maximum number of events to retrieve.
- **`top_n_values`**: (integer, default=25) Number of top occurrences to include in analysis.
- **`policy_groups`**: (list, default=[]) Policy groups to filter events by. Default is an empty list, which means collect events for all Policy Groups.

For optional parameters, there is no need to set them in your YAML unless you want to override the default. Omitting the settings will result in the default being used.

Note: Testing indicates that setting `max_event_quantity` > 10M may result in out of memory issues. If you have data sets larger than this, it is recommended to narrow the window of time (decrease `lookback_hours`) instead of increasing `max_event_quantity`.


### Example YAML Configuration

```yaml
api_key: foo.bar.managedwhitelisting.com
server_name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
event_summary_exporter:
  lookback_hours: 168
  event_types:
#   - 0  #Trusted Execution 
#   - 1  #Blocked Execution 
   - 2  #Untrusted Execution [Audit] 
#   - 3  #Untrusted Execution [OTP] 
#   - 4  #Trusted Path Execution 
#   - 5  #Trusted Publisher Execution 
#   - 6  #Blocklist Execution 
#   - 7  #Blocklist Execution [Audit] 
#   - 8  #Trusted Process Execution
  max_event_quantity: 1000000
  top_n_values: 25
  policy_groups:
    - Workstations Audit
    - Servers Audit
```

## Output

The script generates an Excel file with the name format:
`<server_name>_event_summary_<start_time>_to_<end_time>_<record_count>.xlsx`

### Output Structure

The Excel file contains one worksheet per analyzed field, each with the following structure:

1. **Columns**:
   - **Field Name**: Name of the analyzed field.
   - **Count**: Number of occurrences of each unique value.
   - **Percentage**: Percentage of total occurrences for each value.

2. **Column Width**:
   - Column widths are automatically adjusted for readability, with the "Percentage" column formatted as a percentage.

### Example Worksheet Layout

| ppprocess_name   | Count   | Percentage |
|------------------|---------|------------|
| foo.exe          | 9000    | 9.00%      |
| bar.exe          | 7500    | 7.50%      |
| ...              | ...     | ...        |
| process_n        | 500     | 0.50%      |

Each worksheet shows the most common `top_n_values` for the specific field, as configured.