#!/usr/bin/env python3
"""
Monitor an Airlock Digital server for Enforcement Agents in Safe Mode and
send grouped notifications to Slack.

Behavior
--------
1. Calls POST /v1/agent/find?status=3 to retrieve all Safe Mode agents.
2. Calls POST /v1/group to retrieve policy group names.
3. Adds the policy group name to each Safe Mode agent.
4. Compares the current Safe Mode agent IDs with the previous successful run.
5. Sends a Slack notification for:
   - Only newly detected Safe Mode agents by default
   - All current Safe Mode agents when --notify-all is specified
6. Stores the current Safe Mode agent IDs in a local JSON state file.

State tracking
--------------
The state file stores the agents that were in Safe Mode during the previous
successful check.

Example:
- Run 1: Agent A is in Safe Mode -> notification sent for Agent A
- Run 2: Agent A remains in Safe Mode -> no notification
- Run 3: Agent A is no longer in Safe Mode -> state is updated
- Run 4: Agent A returns to Safe Mode -> notification sent again

The state file is updated only after:
- Airlock Digital API data is retrieved successfully, and
- Any required Slack notification is sent successfully

If no Slack notification is required, the state file is updated immediately.

Requirements
------------
Python 3.9+
requests

Install requests:
    python3 -m pip install requests

Examples
--------
Notify only when agents newly enter Safe Mode:

    python3 airlock_safe_mode_monitor.py \
        --server airlock.example.com \
        --api-key YOUR_API_KEY \
        --slack-webhook "https://hooks.slack.com/services/..." 

Notify on every currently Safe Mode agent during every run:

    python3 airlock_safe_mode_monitor.py \
        --server airlock.example.com \
        --api-key YOUR_API_KEY \
        --slack-webhook "https://hooks.slack.com/services/..." \
        --notify-all

Use a lab server with a self-signed certificate:

    python3 airlock_safe_mode_monitor.py \
        --server lab.example.com \
        --api-key YOUR_API_KEY \
        --slack-webhook "https://hooks.slack.com/services/..." \
        --insecure

Use a specific state file:

    python3 airlock_safe_mode_monitor.py \
        --server airlock.example.com \
        --api-key YOUR_API_KEY \
        --slack-webhook "https://hooks.slack.com/services/..." \
        --state-file /var/lib/airlock/safe_mode_state.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


AIRLOCK_API_PORT = 3129
REQUEST_TIMEOUT_SECONDS = 30
UNKNOWN_GROUP_NAME = "Unknown Policy Group"


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Monitor Airlock Digital Enforcement Agents in Safe Mode and "
            "send grouped notifications to Slack."
        )
    )

    parser.add_argument(
        "--server",
        required=True,
        help=(
            "Airlock Digital server hostname or URL. Port 3129 is applied "
            "automatically."
        ),
    )
    parser.add_argument(
        "--api-key",
        required=True,
        help="Airlock Digital REST API key.",
    )
    parser.add_argument(
        "--slack-webhook",
        required=True,
        help="Slack incoming webhook URL.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable SSL certificate verification. Intended only for lab "
            "servers with self-signed certificates."
        ),
    )
    parser.add_argument(
        "--notify-all",
        action="store_true",
        help=(
            "Notify on all currently Safe Mode agents during every run instead "
            "of only agents newly detected in Safe Mode."
        ),
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help=(
            "Path to the JSON state file. By default, a server-specific file "
            "is created in the current directory."
        ),
    )

    return parser.parse_args()


def normalize_server(server: str) -> tuple[str, str]:
    """
    Normalize the user-supplied server value.

    Returns:
        A tuple containing:
        - Base API URL in the form https://hostname:3129
        - Hostname used when generating the default state filename

    Any supplied scheme, path, query string, or port is removed. Airlock
    Digital REST API traffic is always directed to HTTPS port 3129.
    """

    value = server.strip()

    # urlparse treats a bare hostname as a path, so prepend // when no scheme
    # is present to make it parse as a network location.
    parsed = urlparse(value if "://" in value else f"//{value}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Unable to determine a hostname from: {server}")

    return f"https://{hostname}:{AIRLOCK_API_PORT}", hostname


def default_state_file(hostname: str) -> Path:
    """
    Build a server-specific default state filename.

    Only the portion before the first period is used, matching the naming
    convention commonly used for Airlock Digital server scripts.
    """

    short_server_name = hostname.split(".", 1)[0]
    return Path(f"airlock_safe_mode_state_{short_server_name}.json")


def airlock_post(
    base_url: str,
    endpoint: str,
    api_key: str,
    verify_ssl: bool,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Send a POST request to an Airlock Digital REST API endpoint.

    Parameters are supplied in the URL query string through requests' params
    argument. No JSON request body is used for the endpoints in this script.
    """

    response = requests.post(
        f"{base_url}{endpoint}",
        headers={
            "X-ApiKey": api_key,
            "Accept": "application/json",
        },
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
        verify=verify_ssl,
    )
    response.raise_for_status()

    payload = response.json()

    # Airlock Digital commonly returns HTTP 200 with an application-level
    # status in the "error" field.
    if payload.get("error") != "Success":
        raise RuntimeError(
            f"Airlock Digital API returned: {payload.get('error', 'Unknown error')}"
        )

    return payload


def get_safe_mode_agents(
    base_url: str,
    api_key: str,
    verify_ssl: bool,
) -> list[dict[str, Any]]:
    """Retrieve all Airlock Enforcement Agents currently in Safe Mode."""

    payload = airlock_post(
        base_url=base_url,
        endpoint="/v1/agent/find",
        api_key=api_key,
        verify_ssl=verify_ssl,
        params={"status": 3},
    )

    return payload.get("response", {}).get("agents", [])


def get_policy_groups(
    base_url: str,
    api_key: str,
    verify_ssl: bool,
) -> list[dict[str, Any]]:
    """Retrieve all policy groups from the Airlock Digital server."""

    payload = airlock_post(
        base_url=base_url,
        endpoint="/v1/group",
        api_key=api_key,
        verify_ssl=verify_ssl,
    )

    return payload.get("response", {}).get("groups", [])


def add_group_names(
    agents: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Add a groupname field to each agent.

    A copied agent dictionary is returned so the original API response data is
    not modified in place.
    """

    group_names_by_id = {
        str(group.get("groupid")): str(group.get("name"))
        for group in groups
        if group.get("groupid") and group.get("name")
    }

    enriched_agents: list[dict[str, Any]] = []

    for agent in agents:
        enriched_agent = dict(agent)
        group_id = str(agent.get("groupid", ""))
        enriched_agent["groupname"] = group_names_by_id.get(
            group_id,
            UNKNOWN_GROUP_NAME,
        )
        enriched_agents.append(enriched_agent)

    return enriched_agents


def load_previous_safe_mode_agent_ids(state_file: Path) -> set[str]:
    """
    Load the previous Safe Mode agent IDs from disk.

    A missing state file is treated as the first run. Minimal validation is
    performed because the file is generated and maintained by this script.
    """

    if not state_file.exists():
        return set()

    with state_file.open("r", encoding="utf-8") as handle:
        state = json.load(handle)

    return set(state.get("safe_mode_agent_ids", []))


def save_current_state(
    state_file: Path,
    hostname: str,
    agents: list[dict[str, Any]],
) -> None:
    """Write the current Safe Mode agent IDs and basic details to disk."""

    state_file.parent.mkdir(parents=True, exist_ok=True)

    state = {
        "server": hostname,
        "safe_mode_agent_ids": sorted(
            str(agent["agentid"])
            for agent in agents
            if agent.get("agentid")
        ),
        "safe_mode_agents": [
            {
                "agentid": agent.get("agentid"),
                "hostname": agent.get("hostname"),
                "groupid": agent.get("groupid"),
                "groupname": agent.get("groupname"),
            }
            for agent in sorted(
                agents,
                key=lambda item: (
                    str(item.get("groupname", "")).casefold(),
                    str(item.get("hostname", "")).casefold(),
                ),
            )
        ],
    }

    temporary_file = state_file.with_suffix(f"{state_file.suffix}.tmp")

    with temporary_file.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)
        handle.write("\n")

    temporary_file.replace(state_file)


def select_agents_to_notify(
    current_agents: list[dict[str, Any]],
    previous_agent_ids: set[str],
    notify_all: bool,
) -> list[dict[str, Any]]:
    """Select either all current agents or only newly detected agents."""

    if notify_all:
        return current_agents

    return [
        agent
        for agent in current_agents
        if agent.get("agentid")
        and str(agent["agentid"]) not in previous_agent_ids
    ]


def build_slack_message(
    agents: list[dict[str, Any]],
    notify_all: bool,
) -> str:
    """Build the plain-text Slack notification grouped by policy group."""

    agents_by_group: dict[str, list[str]] = defaultdict(list)

    for agent in agents:
        group_name = str(agent.get("groupname") or UNKNOWN_GROUP_NAME)
        hostname = str(agent.get("hostname") or agent.get("agentid") or "Unknown Agent")
        agents_by_group[group_name].append(hostname)

    agent_count = len(agents)
    group_count = len(agents_by_group)

    agent_word = "Agent" if agent_count == 1 else "Agents"
    group_word = "Policy Group" if group_count == 1 else "Policy Groups"

    if notify_all:
        opening = (
            f"{agent_count} Airlock Enforcement {agent_word} in "
            f"{group_count} {group_word} are currently in Safe Mode. "
            "Details below."
        )
    else:
        opening = (
            f"{agent_count} Airlock Enforcement {agent_word} in "
            f"{group_count} {group_word} moved to Safe Mode since the last "
            "check. Details below."
        )

    lines = [opening]

    for group_name in sorted(agents_by_group, key=str.casefold):
        lines.append("")
        lines.append(f"*{group_name}*")

        for hostname in sorted(agents_by_group[group_name], key=str.casefold):
            lines.append(f"• {hostname}")

    return "\n".join(lines)


def send_slack_notification(webhook_url: str, message: str) -> None:
    """Send a message to Slack through an incoming webhook."""

    response = requests.post(
        webhook_url,
        json={"text": message},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()


def main() -> int:
    """Run the Safe Mode monitoring workflow."""

    args = parse_arguments()

    try:
        base_url, hostname = normalize_server(args.server)
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    verify_ssl = not args.insecure
    state_file = args.state_file or default_state_file(hostname)

    if not verify_ssl:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sys.stderr.write(
            "\n\033[91m"
            "!!! INSECURE MODE ENABLED !!!\n"
            "SSL certificate verification is DISABLED.\n"
            "\n"
            "This means:\n"
            "  • Your connection is not secure.\n"
            "  • An attacker on the network could intercept or modify traffic.\n"
            "  • This option should only be used in a trusted lab environment.\n"
            "\033[0m\n"
        )

    print("Airlock Digital Safe Mode monitor")
    print(f"\tServer: {hostname}")
    print(f"\tAPI URL: {base_url}")
    print(f"\tAPI key ending in: '{args.api_key[-4:]}'")
    print(f"\tSSL verification: {'Enabled' if verify_ssl else 'Disabled'}")
    print(f"\tNotification mode: {'All Safe Mode agents' if args.notify_all else 'Newly detected agents only'}")
    print(f"\tState file: {state_file}")

    try:
        previous_agent_ids = load_previous_safe_mode_agent_ids(state_file)

        print("\nRetrieving Safe Mode agents...")
        safe_mode_agents = get_safe_mode_agents(
            base_url=base_url,
            api_key=args.api_key,
            verify_ssl=verify_ssl,
        )
        print(f"\tFound {len(safe_mode_agents)} Safe Mode agent(s)")

        print("Retrieving policy groups...")
        policy_groups = get_policy_groups(
            base_url=base_url,
            api_key=args.api_key,
            verify_ssl=verify_ssl,
        )
        print(f"\tFound {len(policy_groups)} policy group(s)")

        enriched_agents = add_group_names(safe_mode_agents, policy_groups)

        agents_to_notify = select_agents_to_notify(
            current_agents=enriched_agents,
            previous_agent_ids=previous_agent_ids,
            notify_all=args.notify_all,
        )

        if agents_to_notify:
            message = build_slack_message(
                agents=agents_to_notify,
                notify_all=args.notify_all,
            )

            print(
                f"Sending Slack notification for "
                f"{len(agents_to_notify)} agent(s)..."
            )
            send_slack_notification(args.slack_webhook, message)
            print("\tSlack notification sent")
        else:
            if args.notify_all:
                print("No Safe Mode agents found. No Slack notification sent.")
            else:
                print(
                    "No newly detected Safe Mode agents. "
                    "No Slack notification sent."
                )

        save_current_state(
            state_file=state_file,
            hostname=hostname,
            agents=enriched_agents,
        )
        print(f"State saved to: {state_file}")

    except (
        OSError,
        json.JSONDecodeError,
        requests.RequestException,
        RuntimeError,
        KeyError,
    ) as exc:
        sys.stderr.write(f"\nError: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
