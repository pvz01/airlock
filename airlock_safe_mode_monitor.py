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
import hashlib
import json
import os
import sys
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterator
from urllib.parse import urlparse

import requests


AIRLOCK_API_PORT = 3129
REQUEST_TIMEOUT_SECONDS = 30
UNKNOWN_GROUP_NAME = "Unknown Policy Group"
SLACK_TEXT_LIMIT = 35_000


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
        default=os.environ.get("AIRLOCK_API_KEY"),
        help="Airlock Digital REST API key (or set AIRLOCK_API_KEY).",
    )
    parser.add_argument(
        "--slack-webhook",
        default=os.environ.get("SLACK_WEBHOOK_URL"),
        help="Slack incoming webhook URL (or set SLACK_WEBHOOK_URL).",
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
    if "://" not in value and value.count(":") >= 2 and not value.startswith("["):
        parsed = urlparse(f"//[{value}]")
    else:
        parsed = urlparse(value if "://" in value else f"//{value}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Unable to determine a hostname from: {server}")

    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Server must contain only a hostname (and optional scheme)")
    if parsed.port not in (None, AIRLOCK_API_PORT):
        raise ValueError(f"Airlock API port must be {AIRLOCK_API_PORT}")

    url_hostname = f"[{hostname}]" if ":" in hostname else hostname
    return f"https://{url_hostname}:{AIRLOCK_API_PORT}", hostname


def default_state_file(hostname: str) -> Path:
    """
    Build a server-specific default state filename.

    Only the portion before the first period is used, matching the naming
    convention commonly used for Airlock Digital server scripts.
    """

    safe_name = "".join(character if character.isalnum() or character in "-_" else "_" for character in hostname)
    digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:10]
    return Path(f"airlock_safe_mode_state_{safe_name}_{digest}.json")


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
    if not isinstance(payload, dict):
        raise RuntimeError("Airlock Digital API returned a non-object JSON payload")

    # Airlock Digital commonly returns HTTP 200 with an application-level
    # status in the "error" field.
    if payload.get("error") != "Success":
        raise RuntimeError(
            f"Airlock Digital API returned: {payload.get('error', 'Unknown error')}"
        )

    return payload


def required_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a required response list, rejecting unknown or malformed results."""

    response = payload.get("response")
    if not isinstance(response, dict) or key not in response:
        raise RuntimeError(f"Airlock Digital API response is missing response.{key}")
    values = response[key]
    if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
        raise RuntimeError(f"Airlock Digital API response.{key} must be a list of objects")
    return values


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

    return required_list(payload, "agents")


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

    return required_list(payload, "groups")


def canonicalize_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize IDs and deterministically deduplicate eligible agent records."""

    by_id: dict[str, dict[str, Any]] = {}
    for agent in agents:
        raw_id = agent.get("agentid")
        if raw_id is None or not str(raw_id).strip():
            continue
        agent_id = str(raw_id).strip()
        normalized = dict(agent)
        normalized["agentid"] = agent_id
        # Stable serialization makes the result independent of API ordering.
        existing = by_id.get(agent_id)
        if existing is None or json.dumps(normalized, sort_keys=True, default=str) < json.dumps(existing, sort_keys=True, default=str):
            by_id[agent_id] = normalized
    return [by_id[agent_id] for agent_id in sorted(by_id)]


def add_group_names(
    agents: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Add a groupname field to each agent.

    A copied agent dictionary is returned so the original API response data is
    not modified in place.
    """

    group_names_by_id: dict[str, str] = {}
    for group in groups:
        if group.get("groupid") and group.get("name"):
            group_id = str(group["groupid"])
            group_name = str(group["name"])
            existing = group_names_by_id.get(group_id)
            if existing is None or (group_name.casefold(), group_name) < (existing.casefold(), existing):
                group_names_by_id[group_id] = group_name

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
    if not isinstance(state, dict):
        raise ValueError("State file must contain a JSON object")
    ids = state.get("safe_mode_agent_ids")
    if not isinstance(ids, list):
        raise ValueError("State file safe_mode_agent_ids must be a list")
    if any(value is None or not isinstance(value, (str, int)) or not str(value).strip() for value in ids):
        raise ValueError("State file contains an invalid agent ID")
    return {str(value).strip() for value in ids}


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
                (agent for agent in agents if agent.get("agentid")),
                key=lambda item: (
                    str(item.get("groupname", "")).casefold(),
                    str(item.get("hostname", "")).casefold(),
                ),
            )
        ],
    }

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile("w", encoding="utf-8", dir=state_file.parent, prefix=f".{state_file.name}.", suffix=".tmp", delete=False) as handle:
            temporary_path = Path(handle.name)
            json.dump(state, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(state_file)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@contextmanager
def state_lock(state_file: Path) -> Iterator[None]:
    """Hold an exclusive lock for the complete read/check/notify/write cycle."""

    state_file.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_file.with_name(f"{state_file.name}.lock")
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            if handle.tell() == 0 and handle.read(1) == b"":
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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


def build_slack_messages(
    agents: list[dict[str, Any]],
    notify_all: bool,
    text_limit: int = SLACK_TEXT_LIMIT,
) -> list[str]:
    """Split notifications into bounded messages without dropping agents."""

    if text_limit <= 0:
        raise ValueError("Slack text limit must be positive")
    messages: list[str] = []
    chunk: list[dict[str, Any]] = []
    for agent in agents:
        candidate = [*chunk, agent]
        candidate_message = build_slack_message(candidate, notify_all)
        if len(candidate_message) <= text_limit:
            chunk = candidate
            continue
        if not chunk:
            raise ValueError(f"Agent {agent.get('agentid')} cannot fit in a Slack message")
        messages.append(build_slack_message(chunk, notify_all))
        chunk = [agent]
        if len(build_slack_message(chunk, notify_all)) > text_limit:
            raise ValueError(f"Agent {agent.get('agentid')} cannot fit in a Slack message")
    if chunk:
        messages.append(build_slack_message(chunk, notify_all))
    return messages


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

    if not args.api_key or not args.slack_webhook:
        sys.stderr.write(
            "Error: provide --api-key and --slack-webhook, or set "
            "AIRLOCK_API_KEY and SLACK_WEBHOOK_URL\n"
        )
        return 2

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
    print(f"\tSSL verification: {'Enabled' if verify_ssl else 'Disabled'}")
    print(f"\tNotification mode: {'All Safe Mode agents' if args.notify_all else 'Newly detected agents only'}")
    print(f"\tState file: {state_file}")

    try:
        with state_lock(state_file):
            return run_check(args, base_url, hostname, verify_ssl, state_file)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        requests.RequestException,
        RuntimeError,
        KeyError,
    ) as exc:
        sys.stderr.write(f"\nError: {exc}\n")
        return 1


def run_check(
    args: argparse.Namespace,
    base_url: str,
    hostname: str,
    verify_ssl: bool,
    state_file: Path,
) -> int:
    """Run one serialized monitoring transaction."""

    previous_agent_ids = load_previous_safe_mode_agent_ids(state_file)

    print("\nRetrieving Safe Mode agents...")
    safe_mode_agents = canonicalize_agents(get_safe_mode_agents(
            base_url=base_url,
            api_key=args.api_key,
            verify_ssl=verify_ssl,
        ))
    print(f"\tFound {len(safe_mode_agents)} eligible Safe Mode agent(s)")

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
        messages = build_slack_messages(agents_to_notify, args.notify_all)
        print(f"Sending {len(messages)} Slack notification(s) for {len(agents_to_notify)} agent(s)...")
        for message in messages:
            send_slack_notification(args.slack_webhook, message)
        print("\tSlack notification(s) sent")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
