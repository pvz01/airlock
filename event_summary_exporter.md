# Event Summary Exporter Documentation

## Overview

This script, [event_summary_exporter.py](event_summary_exporter.py) automates the process of exporting and analyzing execution history (event) data from an Airlock server. It identifies and reports on the most common activity patterns, focusing on "Untrusted Execution [Audit]" events to help reduce overall event volume and prepare for transitioning to Enforcement Mode. The output is a structured Excel report that summarizes the most frequent values in key fields.

### License
This script is published under the GNU General Public License v3.0 and is intended as a practical example of how to interact with the [Airlock Digital REST API](https://api.airlockdigital.com/). It is not a commercial product and is provided 'as-is' with no support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

### Prerequisites
The script requires:
- An API key with `logging/exechistories` permission.
- Python libraries: `requests`, `pandas`, `yaml`, `openpyxl`, `bson`.

## Functionality

The script performs the following tasks:

1. **Load Configuration**: Reads configuration settings from a YAML file (`airlock.yaml`) to specify event filters and output details.
2. **Calculate Checkpoint**: Sets a checkpoint to retrieve only events within the specified lookback period.
3. **Download Events**: Retrieves event data from the Airlock server in batches, using the checkpoint to filter by time.
4. **Process Data**:
   - Anonymizes usernames in file paths.
   - Renames key columns for clarity.
   - Splits fully-qualified filenames into folder and file components.
5. **Analyze Data**: Identifies and counts the top N most common values for each selected field.
6. **Export Results**: Outputs the analyzed data to an Excel file, with column formatting and summary worksheets.

## Configuration File (YAML)

The script reads from a YAML configuration file (`airlock.yaml`) with the following structure. The configuration settings are under the section **`event_summary_exporter`**.

### Required Properties

- **`api_key`**: (string) The API key for authenticating with the Airlock server.
- **`server_name`**: (string) The server's hostname or IP address.

### Optional Properties

- **`lookback_hours`**: (integer, default=168) The number of hours to look back for event retrieval. Defaults to one week (168 hours).
- **`event_types`**: (list of integers, default=[2]) Event types to retrieve. Default is `2` (Untrusted Execution [Audit]).
- **`max_event_quantity`**: (integer, default=10,000,000) Maximum number of events to retrieve.
- **`top_n_values`**: (integer, default=25) Number of top occurrences to include in analysis.
- **`policy_groups`**: (list, default=[]) Policy groups to filter events by. Defaults to all policy groups.

### Example YAML Configuration

```yaml
api_key: foo.bar.managedwhitelisting.com
server_name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
event_summary_exporter:
  lookback_hours: 168
  event_types: [2, 3]
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
| foo.exe          | 10000   | 80.00%     |
| bar.exe          | 1000    | 8.00%      |

Each worksheet shows the most common `top_n_values` for the specific field, as configured.