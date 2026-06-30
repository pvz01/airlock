#!/usr/bin/env python3
"""
dump_policies.py
Patrick Van Zandt, Principal Technical Success Engineer

Exports policy configuration from an Airlock Digital Server using the public REST API.

This script is intended for:

- Archival and backup of policy configuration
- Audit and external review
- Documentation of an Airlock deployment
- Assisting migration to another Airlock Digital Server

Where possible, reusable objects are saved in the same XML format used by
the management console's Export/Import functionality, allowing them to be
imported directly into another server via the GUI.

Output includes:

- Policy group list (JSON)
- Individual policy group policy configuration (JSON)
- Paths, publishers and processes for each policy group (portable XML + TXT)
- Allowlists, baselines, and blocklists for each policy group (TXT)
- Referenced allowlists, baselines and blocklists (portable XML)

Requirements

An API key with permission to access the following REST API endpoints:

    /v1/group
    /v1/group/policies
    /v1/application/export
    /v1/baseline/export
    /v1/blocklist/export

Usage

python dump_policies.py --server yourserver.example.com --api-key YOUR_API_KEY

"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

import requests
import urllib3


def get_server_alias(server):
    """Return first part of FQDN, lowercased."""
    return server.split('.')[0].lower()


def get_timestamp():
    """Return UTC timestamp friendly for filenames."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M_utc').lower()


def safe_filename(value):
    """Make a value safe for use as a filename."""
    value = str(value).strip().replace(' ', '_')
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', value)
    return value or 'unnamed'


def normalize_windows_path(value):
    """
    The API may return Windows paths with doubled backslashes.
    GUI import expects normal single-backslash Windows paths.
    """
    value = '' if value is None else str(value)
    return value.replace('\\\\', '\\')


def post(server, api_key, endpoint, params=None, verify_ssl=True):
    """Send POST request to Airlock API."""
    url = f'https://{server}:3129{endpoint}'

    response = requests.post(
        url,
        headers={'X-ApiKey': api_key},
        params=params or {},
        verify=verify_ssl,
        timeout=120,
    )

    response.raise_for_status()
    return response


def save_json(path, data):
    """Save JSON to disk."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def save_text(path, text):
    """Save text/XML/TXT to disk."""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def save_name_list(path, items):
    """Save one human-readable name per line."""
    names = []

    for item in items or []:
        if not isinstance(item, dict):
            continue

        name = (
            item.get('name')
            or item.get('displayname')
            or item.get('applicationid')
            or item.get('baselineid')
            or item.get('blocklistid')
        )

        if name:
            names.append(str(name))

    text = '\n'.join(names)

    if text:
        text += '\n'

    save_text(path, text)


def build_simple_name_txt(items, normalize_paths=False):
    """Build TXT with one name per line."""
    names = []

    for item in items or []:
        if not isinstance(item, dict):
            continue

        name = item.get('name')

        if name:
            if normalize_paths:
                name = normalize_windows_path(name)

            names.append(str(name))

    text = '\n'.join(names)

    if text:
        text += '\n'

    return text


def build_processes_txt(pprocesses, gprocesses):
    """Build TXT with one process per line and human-readable process type."""
    lines = []

    for process in pprocesses or []:
        if isinstance(process, dict) and process.get('name'):
            lines.append(f'{process.get("name")} (Parent Process)')

    for process in gprocesses or []:
        if isinstance(process, dict) and process.get('name'):
            lines.append(f'{process.get("name")} (Grandparent Process)')

    text = '\n'.join(lines)

    if text:
        text += '\n'

    return text


def cdata(value):
    """Wrap value in CDATA."""
    value = '' if value is None else str(value)
    value = value.replace(']]>', ']]]]><![CDATA[>')
    return f'<![CDATA[{value}]]>'


def get_response(value):
    """Return Airlock response object when present."""
    if isinstance(value, dict) and 'response' in value:
        return value['response']

    return value


def as_list(value):
    """Normalize common Airlock response shapes into a list."""
    value = get_response(value)

    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        for key in ('groups', 'policies', 'applications', 'baselines', 'blocklists', 'data', 'items', 'results'):
            if isinstance(value.get(key), list):
                return value[key]

    return []


def get_policy_body(policy_json):
    """Return the policy body from an Airlock API response."""
    body = get_response(policy_json)

    if isinstance(body, dict):
        return body

    return {}


def find_package_references(policy_json):
    """
    Find allowlists, baselines, and blocklists directly from policy JSON.

    API name: applications
    UI name: allowlists
    """
    policy = get_policy_body(policy_json)

    found = {
        'allowlist': {},
        'baseline': {},
        'blocklist': {},
    }

    for app in policy.get('applications') or []:
        package_id = app.get('applicationid')
        package_name = app.get('name') or package_id

        if package_id:
            found['allowlist'][str(package_id)] = str(package_name)

    for baseline in policy.get('baselines') or []:
        package_id = baseline.get('baselineid')
        package_name = baseline.get('name') or package_id

        if package_id:
            found['baseline'][str(package_id)] = str(package_name)

    for blocklist in policy.get('blocklists') or []:
        package_id = blocklist.get('blocklistid')
        package_name = blocklist.get('name') or package_id

        if package_id:
            found['blocklist'][str(package_id)] = str(package_name)

    return found


def merge_refs(destination, source):
    """Merge reusable package references."""
    for package_type in destination:
        destination[package_type].update(source[package_type])


def build_paths_xml(paths):
    """Build portable path XML."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<PathExport>',
        '\t<Paths>',
    ]

    for path in paths or []:
        lines.extend([
            '\t\t<path>',
            f'\t\t\t<name>{cdata(normalize_windows_path(path.get("name")))}</name>',
            f'\t\t\t<comment>{cdata(path.get("comment"))}</comment>',
            '\t\t</path>',
        ])

    lines.extend([
        '\t</Paths>',
        '</PathExport>',
        '',
    ])

    return '\n'.join(lines)


def build_publishers_xml(publishers):
    """Build portable publisher XML."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<PublisherExport>',
        '\t<Publishers>',
    ]

    for publisher in publishers or []:
        lines.extend([
            '\t\t<publisher>',
            f'\t\t\t<name>{cdata(publisher.get("name"))}</name>',
            f'\t\t\t<comment>{cdata(publisher.get("comment"))}</comment>',
            '\t\t</publisher>',
        ])

    lines.extend([
        '\t</Publishers>',
        '</PublisherExport>',
        '',
    ])

    return '\n'.join(lines)


def build_processes_xml(pprocesses, gprocesses):
    """Build portable process XML."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<ProcessExport>',
        '\t<Processes>',
    ]

    for process in pprocesses or []:
        lines.extend([
            '\t\t<process>',
            f'\t\t\t<proctype>{cdata("pprocess")}</proctype>',
            f'\t\t\t<name>{cdata(process.get("name"))}</name>',
            '\t\t</process>',
        ])

    for process in gprocesses or []:
        lines.extend([
            '\t\t<process>',
            f'\t\t\t<proctype>{cdata("gprocess")}</proctype>',
            f'\t\t\t<name>{cdata(process.get("name"))}</name>',
            '\t\t</process>',
        ])

    lines.extend([
        '\t</Processes>',
        '</ProcessExport>',
        '',
    ])

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Dump Airlock policy groups, policies, and referenced reusable packages.'
    )

    parser.add_argument('--server', required=True, help='Airlock server hostname, without https:// or port')
    parser.add_argument('--api-key', required=True, help='Airlock API key')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification')

    args = parser.parse_args()

    verify_ssl = not args.insecure

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print('WARNING: SSL certificate verification is disabled.')

    server_alias = get_server_alias(args.server)
    timestamp = get_timestamp()

    output_dir = f'airlock_policy_export_{server_alias}_{timestamp}'
    policies_dir = os.path.join(output_dir, 'policies')
    allowlists_dir = os.path.join(output_dir, 'allowlists')
    baselines_dir = os.path.join(output_dir, 'baselines')
    blocklists_dir = os.path.join(output_dir, 'blocklists')

    for folder in (output_dir, policies_dir, allowlists_dir, baselines_dir, blocklists_dir):
        os.makedirs(folder, exist_ok=True)

    print()
    print('Airlock policy/package dump')
    print('---------------------------')
    print(f'Server:     {args.server}')
    print('Port:       3129')
    print(f"API key:    ending in '{args.api_key[-4:]}'")
    print(f'Output dir: {output_dir}')
    print('Folders:')
    print('  policies/')
    print('  allowlists/')
    print('  baselines/')
    print('  blocklists/')
    print()

    print('[1/3] Downloading policy group list...')

    response = post(args.server, args.api_key, '/v1/group', verify_ssl=verify_ssl)
    groups_json = response.json()

    groups_path = os.path.join(output_dir, 'policy_group_list.json')
    save_json(groups_path, groups_json)

    groups = as_list(groups_json)

    print(f'      Saved: {groups_path}')
    print(f'      Groups found: {len(groups)}')
    print()

    print('[2/3] Downloading policy group details...')

    all_package_refs = {
        'allowlist': {},
        'baseline': {},
        'blocklist': {},
    }

    for group_number, group in enumerate(groups, start=1):
        group_id = group.get('groupid') or group.get('id')
        group_name = group.get('name') or group.get('groupname') or group_id

        if not group_id:
            print(f'      Group {group_number} of {len(groups)}: skipping group with no groupid/id.')
            print()
            continue

        safe_group_name = safe_filename(group_name)
        group_output_dir = os.path.join(policies_dir, safe_group_name)
        os.makedirs(group_output_dir, exist_ok=True)

        print(f'      Group {group_number} of {len(groups)}: {group_name} ({group_id})')

        response = post(
            args.server,
            args.api_key,
            '/v1/group/policies',
            params={'groupid': group_id},
            verify_ssl=verify_ssl,
        )

        policy_json = response.json()
        policy_body = get_policy_body(policy_json)

        json_path = os.path.join(group_output_dir, f'{safe_group_name}_policies.json')

        paths_xml_path = os.path.join(group_output_dir, f'{safe_group_name}_paths.xml')
        publishers_xml_path = os.path.join(group_output_dir, f'{safe_group_name}_publishers.xml')
        processes_xml_path = os.path.join(group_output_dir, f'{safe_group_name}_processes.xml')

        paths_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_paths.txt')
        publishers_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_publishers.txt')
        processes_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_processes.txt')

        allowlists_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_allowlists.txt')
        baselines_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_baselines.txt')
        blocklists_txt_path = os.path.join(group_output_dir, f'{safe_group_name}_blocklists.txt')

        save_json(json_path, policy_json)

        save_text(paths_xml_path, build_paths_xml(policy_body.get('paths')))
        save_text(publishers_xml_path, build_publishers_xml(policy_body.get('publishers')))
        save_text(processes_xml_path, build_processes_xml(policy_body.get('pprocesses'), policy_body.get('gprocesses')))

        save_text(paths_txt_path, build_simple_name_txt(policy_body.get('paths'), normalize_paths=True))
        save_text(publishers_txt_path, build_simple_name_txt(policy_body.get('publishers')))
        save_text(processes_txt_path, build_processes_txt(policy_body.get('pprocesses'), policy_body.get('gprocesses')))

        save_name_list(allowlists_txt_path, policy_body.get('applications'))
        save_name_list(baselines_txt_path, policy_body.get('baselines'))
        save_name_list(blocklists_txt_path, policy_body.get('blocklists'))

        refs = find_package_references(policy_json)
        merge_refs(all_package_refs, refs)

        print(f'        Saved: {json_path}')
        print(f'        Saved: {paths_xml_path}')
        print(f'        Saved: {publishers_xml_path}')
        print(f'        Saved: {processes_xml_path}')
        print(f'        Saved: {paths_txt_path}')
        print(f'        Saved: {publishers_txt_path}')
        print(f'        Saved: {processes_txt_path}')
        print(f'        Saved: {allowlists_txt_path}')
        print(f'        Saved: {baselines_txt_path}')
        print(f'        Saved: {blocklists_txt_path}')
        print()

    print('      Completed policy group export.')
    print()
    print('      Unique referenced reusable packages found:')
    print(f'        Allowlists: {len(all_package_refs["allowlist"])}')
    print(f'        Baselines:  {len(all_package_refs["baseline"])}')
    print(f'        Blocklists: {len(all_package_refs["blocklist"])}')
    print()

    print('[3/3] Exporting referenced reusable packages as XML...')

    export_config = {
        'allowlist': {
            'endpoint': '/v1/application/export',
            'id_param': 'applicationid',
            'folder': allowlists_dir,
            'label': 'Allowlist',
        },
        'baseline': {
            'endpoint': '/v1/baseline/export',
            'id_param': 'baselineid',
            'folder': baselines_dir,
            'label': 'Baseline',
        },
        'blocklist': {
            'endpoint': '/v1/blocklist/export',
            'id_param': 'blocklistid',
            'folder': blocklists_dir,
            'label': 'Blocklist',
        },
    }

    for package_type, packages in all_package_refs.items():
        config = export_config[package_type]
        total_packages = len(packages)

        print(f'      {config["label"]}s: {total_packages}')

        for package_number, (package_id, package_name) in enumerate(packages.items(), start=1):
            print(
                f'        {config["label"]} {package_number} of {total_packages}: '
                f'{package_name} ({package_id})'
            )

            response = post(
                args.server,
                args.api_key,
                config['endpoint'],
                params={config['id_param']: package_id},
                verify_ssl=verify_ssl,
            )

            filename = f'{safe_filename(package_name)}.xml'
            path = os.path.join(config['folder'], filename)

            save_text(path, response.text)

            print(f'          Saved: {path}')

        print()

    print('Export complete.')
    print()
    print(f'Output folder: {output_dir}')
    print()
    print('Summary:')
    print(f'  Policy groups : {len(groups)}')
    print(f'  Allowlists    : {len(all_package_refs["allowlist"])}')
    print(f'  Baselines     : {len(all_package_refs["baseline"])}')
    print(f'  Blocklists    : {len(all_package_refs["blocklist"])}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        print('Cancelled by user.')
        sys.exit(1)