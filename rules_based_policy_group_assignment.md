# Script Documentation: `rules_based_policy_group_assignment.py`

## 1. **Script Overview**
The [rules_based_policy_group_assignment.py](rules_based_policy_group_assignment.py) script dynamically assigns agents to specific policy groups based on configurable rules. The script retrieves a list of agents from a server, categorizes them based on hostname or operating system criteria, and moves them to the correct policy group if necessary. Each agent's movement is logged to a CSV file, which can be customized via the configuration file.

### License
This script is published under the GNU General Public License v3.0 and is intended as a practical example of how to interact with the [Airlock Digital REST API](https://api.airlockdigital.com/). It is not a commercial product and is provided 'as-is' with no support. No warranty, express or implied, is provided, and the use of this script is at your own risk.

### Key Features
- **Dynamic Agent Categorization**: Agents are categorized based on hostname patterns or operating system rules specified in a YAML configuration file.
- **Policy Group Assignment**: Agents are moved to specific policy groups if their current group does not match the expected group.
- **CSV Logging**: The script logs every agent move to a CSV file, tracking details like the timestamp, hostname, agent ID, and group changes.
- **Error Handling**: The script gracefully handles network errors and retries after a specified sleep interval.

---

## 2. **Configuration (YAML File)**

The script uses a YAML configuration file (`airlock.yaml`) to define the server settings, categorization rules, and logging options. Below is an example of the configuration file:

### Example `airlock.yaml`:

```yaml
server_name: foo.bar.managedwhitelisting.com
api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

rules_based_policy_group_assignment:

  interval_between_runs_seconds: 900  # Time (in seconds) to sleep between each iteration

  output_file: rules_based_policy_group_assignment_log.csv  # Name of the output CSV log file

  categories:
    - name: Lab Machines
      hostname_startswith: lab-
      valid_policy_groups: 
        - aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa
        - bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbbb
      target_policy_group: aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa

    - name: Developers
      hostname_substring: 
        start: 3
        end: 6
        match: dev
      valid_policy_groups: 
        - ccccccc3-cccc-cccc-cccc-cccccccccccc
      target_policy_group: ccccccc3-cccc-cccc-cccc-cccccccccccc

    - name: Servers
      os_contains: windows server
      valid_policy_groups: 
        - ddddddd4-dddd-dddd-dddd-dddddddddddd
        - eeeeeee5-eeee-eeee-eeee-eeeeeeeeeeee
        - fffffff6-ffff-ffff-ffff-ffffffffffff
      target_policy_group: ddddddd4-dddd-dddd-dddd-dddddddddddd

    - name: General User Population
      valid_policy_groups: 
        - ggggggg7-gggg-gggg-gggg-gggggggggggg
        - hhhhhhh8-hhhh-hhhh-hhhh-hhhhhhhhhhhh
        - iiiiiii9-iiii-iiii-iiii-iiiiiiiiiiii
        - jjjjjjj0-jjjj-jjjj-jjjj-jjjjjjjjjjjj
      target_policy_group: jjjjjjj0-jjjj-jjjj-jjjj-jjjjjjjjjjjj
```

### Configuration Parameters

- **`server_name`**: The server address where the script retrieves the agent list.
- **`api_key`**: The API key used to authenticate requests.
- **`interval_between_runs_seconds`**: Time (in seconds) the script sleeps between iterations of fetching and processing agents.
- **`output_file`**: Name of the CSV file where agent movements are logged. If the file exists, the script appends data without duplicating headers.
- **`categories`**: Defines the rules for categorizing agents, including:
  - **`name`**: The name of the category.
  - **`hostname_startswith`**, **`hostname_contains`**, or **`hostname_endswith`**: Criteria for matching the agent’s hostname.
  - **`hostname_substring`**: Matches a specific part of the hostname within a defined index range.
  - **`os_contains`**: Criteria for matching the agent’s operating system.
  - **`valid_policy_groups`**: A list of policy group IDs considered valid for this category.
  - **`target_policy_group`**: The policy group ID to which agents are moved if their current group does not match the valid policy groups.

---

## 3. **How to Run the Script**

### Prerequisites
- **Python**: Ensure Python 3.x is installed.
- **Dependencies**: Install the required libraries using pip:
  ```bash
  pip install requests PyYAML python-dateutil

## Running the Script

1. **Edit the Configuration File**:
   - Open `airlock.yaml` and provide values for `server_name`, `api_key`, and rules for categorizing agents.

2. **Run the Script**:
   - Run the script using the following command:
   `python rules_based_policy_group_assignment.py`

3. **Log Output**:
   - The script outputs agent moves to a CSV file (specified in the `output_file` field). Each move logs:
     - Timestamp
     - Hostname
     - Agent category
     - Agent ID
     - Group ID it was moved from
     - Group ID it was moved to

4. **Script Behavior**:
   - The script runs indefinitely, processing agents in batches. After each iteration, it sleeps for the amount of time specified in `interval_between_runs_seconds`.
   - The script can be safely killed and restarted without corrupting the CSV file, as it appends to the existing file and avoids writing duplicate headers.

---

## Troubleshooting

- **Authentication Errors**:
  - Ensure the `api_key` in the configuration is correct and has the necessary permissions to access the API endpoints `agent/move` and `agent/find`.
  
- **Server Not Found**:
  - Verify the `server_name` in the configuration is correct and reachable on port 3129.
  
- **Network Failures**:
  - The script includes retry logic for network errors. In case of failure, it will print an error message and sleep for the defined interval before retrying.

- **CSV Output Issues**:
  - Ensure the `output_file` path is accessible and the script has write permissions to create or append to the file.

---
