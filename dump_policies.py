#!/usr/bin/env python3

"""
dump_policies.py

Patrick Van Zandt, Principal Technical Success Engineer

Exports policy configuration from an Airlock Digital Server using the public
REST API.

This script is intended for:

- Archival and backup of policy configuration
- Audit and external review
- Documentation of an Airlock deployment
- Assisting migration to another Airlock Digital Server

Where possible, allowlists, baselines, and blocklists are saved in the same XML
format used by the management console's Export/Import functionality, allowing
them to be imported directly into another server through the GUI or REST API.

Output includes:

- Human-readable, self-contained HTML policy report
- Hierarchical policy group list with Enforcement Agent counts and policy mode
- Policy group list (JSON)
- Agent list used for Enforcement Agent counts (JSON)
- Individual policy group policy configuration (JSON)
- Paths, publishers and processes for each policy group (portable XML + TXT)
- Allowlists, baselines, and blocklists for each policy group (TXT)
- Referenced allowlists, baselines and blocklists (GUI-import-compatible XML)
- Searchable HTML summaries for exported allowlists, baselines and blocklists

Requirements
An API key with permission to access the following REST API endpoints:

 /v1/group
 /v1/group/policies
 /v1/agent/find
 /v1/application/export
 /v1/baseline/export
 /v1/blocklist/export

Usage

python dump_policies.py --server yourserver.example.com --api-key YOUR_API_KEY
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone

import requests
import urllib3


SCRIPT_VERSION = '2026-07-15.12'
GLOBAL_POLICY_PARENT = 'global-policy-settings'
INHERITABLE_COLLECTIONS = (
    'applications',
    'baselines',
    'blocklists',
    'paths',
    'publishers',
    'pprocesses',
    'gprocesses',
)
EXPORT_COLLECTIONS = {
    'applications': ('allowlist', 'applicationid'),
    'baselines': ('baseline', 'baselineid'),
    'blocklists': ('blocklist', 'blocklistid'),
}


def get_server_alias(server):
    """Return first part of FQDN, lowercased."""
    return server.split('.')[0].lower()


def get_timestamp():
    """Return UTC timestamp friendly for filenames."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M_utc').lower()


def get_display_timestamp():
    """Return a human-readable UTC timestamp."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def safe_filename(value):
    """Make a value safe for use as a filename."""
    value = str(value).strip().replace(' ', '_')
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', value)
    return value or 'unnamed'


def normalize_windows_path(value):
    """Normalize doubled backslashes returned by some API responses."""
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
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_text(path, text):
    """Save text/XML/TXT/HTML to disk."""
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
        for key in (
            'groups',
            'policies',
            'agents',
            'applications',
            'baselines',
            'blocklists',
            'data',
            'items',
            'results',
        ):
            if isinstance(value.get(key), list):
                return value[key]

    return []


def get_policy_body(policy_json):
    """Return the policy body from an Airlock API response."""
    body = get_response(policy_json)
    if isinstance(body, dict):
        return body
    return {}


def find_export_references(policy_json):
    """Find directly assigned allowlists, baselines, and blocklists."""
    policy = get_policy_body(policy_json)
    found = {
        'allowlist': {},
        'baseline': {},
        'blocklist': {},
    }

    for app in policy.get('applications') or []:
        if not isinstance(app, dict):
            continue
        object_id = app.get('applicationid')
        object_name = app.get('name') or object_id
        if object_id:
            found['allowlist'][str(object_id)] = str(object_name)

    for baseline in policy.get('baselines') or []:
        if not isinstance(baseline, dict):
            continue
        object_id = baseline.get('baselineid')
        object_name = baseline.get('name') or object_id
        if object_id:
            found['baseline'][str(object_id)] = str(object_name)

    for blocklist in policy.get('blocklists') or []:
        if not isinstance(blocklist, dict):
            continue
        object_id = blocklist.get('blocklistid')
        object_name = blocklist.get('name') or object_id
        if object_id:
            found['blocklist'][str(object_id)] = str(object_name)

    return found


def merge_refs(destination, source):
    """Merge referenced allowlists, baselines, and blocklists."""
    for object_type in destination:
        destination[object_type].update(source[object_type])


def build_paths_xml(paths):
    """Build portable path XML."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<PathExport>',
        '\t<Paths>',
    ]

    for path in paths or []:
        if not isinstance(path, dict):
            continue
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
        if not isinstance(publisher, dict):
            continue
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
        if not isinstance(process, dict):
            continue
        lines.extend([
            '\t\t<process>',
            f'\t\t\t<proctype>{cdata("pprocess")}</proctype>',
            f'\t\t\t<name>{cdata(process.get("name"))}</name>',
            '\t\t</process>',
        ])

    for process in gprocesses or []:
        if not isinstance(process, dict):
            continue
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


def json_for_html_script(value):
    """Serialize JSON safely for embedding inside an HTML script element."""
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    return (
        text.replace('&', '\\u0026')
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('\u2028', '\\u2028')
        .replace('\u2029', '\\u2029')
    )


def to_bool(value):
    """Interpret common API Boolean representations."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {'true', '1', 'yes', 'enabled', 'on'}:
            return True
        if normalized in {'false', '0', 'no', 'disabled', 'off', ''}:
            return False
    return None


def policy_mode(policy):
    """Return report metadata for the policy group's Audit/Enforcement mode."""
    if 'auditmode' not in policy:
        return {'key': 'unknown', 'label': 'Mode unknown'}
    audit_mode = to_bool(policy.get('auditmode'))
    if audit_mode is True:
        return {'key': 'audit', 'label': 'Audit Mode'}
    if audit_mode is False:
        return {'key': 'enforcement', 'label': 'Enforcement Mode'}
    return {'key': 'unknown', 'label': 'Mode unknown'}


def canonical_key(value):
    """Normalize a setting key for matching."""
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def is_stop_code_key(value):
    """Return True for common Stop Code field spellings."""
    normalized = canonical_key(value)
    return normalized == 'stopcode' or normalized.endswith('stopcode')


def extract_stop_code(value, path=''):
    """Find the first Stop Code value in a nested policy object."""
    if not isinstance(value, dict):
        return None
    for key, child in value.items():
        child_path = f'{path}.{key}' if path else str(key)
        if is_stop_code_key(key):
            enabled = child is not None and str(child).strip() != ''
            encoded = ''
            if enabled:
                encoded = base64.b64encode(str(child).encode('utf-8')).decode('ascii')
            return {
                'path': child_path,
                'enabled': enabled,
                'encoded': encoded,
            }
        if isinstance(child, dict):
            found = extract_stop_code(child, child_path)
            if found:
                return found
    return None


def mask_stop_codes(value):
    """Create an HTML-safe policy copy with Stop Code values masked."""
    if isinstance(value, dict):
        masked = {}
        for key, child in value.items():
            if is_stop_code_key(key):
                masked[key] = '********' if child is not None and str(child).strip() else None
            else:
                masked[key] = mask_stop_codes(child)
        return masked
    if isinstance(value, list):
        return [mask_stop_codes(item) for item in value]
    return value


def group_id(group):
    """Return a policy group ID from common API shapes."""
    return str(group.get('groupid') or group.get('id') or '')


def group_name(group):
    """Return a policy group name from common API shapes."""
    return str(group.get('name') or group.get('groupname') or group_id(group) or 'Unnamed policy group')


def group_parent(group):
    """Return a policy group parent ID."""
    return str(group.get('parent') or GLOBAL_POLICY_PARENT)


def count_agents_by_group(agents):
    """Count Enforcement Agents by group ID."""
    counts = Counter()
    for agent in agents or []:
        if not isinstance(agent, dict):
            continue
        agent_group_id = agent.get('groupid')
        if agent_group_id:
            counts[str(agent_group_id)] += 1
    return counts


def item_identity(collection_key, item):
    """Return a stable identity used to deduplicate inherited assignments."""
    if not isinstance(item, dict):
        return json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)

    id_field = {
        'applications': 'applicationid',
        'baselines': 'baselineid',
        'blocklists': 'blocklistid',
    }.get(collection_key)
    if id_field and item.get(id_field):
        return f'{id_field}:{item.get(id_field)}'

    if item.get('id'):
        return f'id:{item.get("id")}'

    name = item.get('name') or item.get('displayname')
    if name:
        normalized_name = normalize_windows_path(name).strip().lower()
        return f'name:{normalized_name}'

    clean_item = {key: value for key, value in item.items() if key != '_reportMeta'}
    return json.dumps(clean_item, sort_keys=True, ensure_ascii=False, default=str)


def parent_chain(group_id_value, reports_by_id):
    """Return nearest-to-farthest parent reports, stopping on cycles/orphans."""
    chain = []
    seen = {group_id_value}
    current = reports_by_id.get(group_id_value)

    while current:
        parent_id = group_parent(current['group'])
        if not parent_id or parent_id == GLOBAL_POLICY_PARENT or parent_id in seen:
            break
        parent_report = reports_by_id.get(parent_id)
        if not parent_report:
            break
        chain.append(parent_report)
        seen.add(parent_id)
        current = parent_report

    return chain


def build_effective_policies(group_reports):
    """Classify effective assignments as direct or inherited.

    The /v1/group/policies response can include inherited assignments in a
    child group's own collections. An item is therefore inherited when the same
    stable identity appears in an ancestor policy response. This also supports
    server versions that do not repeat inherited assignments in the child
    response by appending missing ancestor items.
    """
    reports_by_id = {
        group_id(report['group']): report
        for report in group_reports
        if group_id(report['group'])
    }

    for report in group_reports:
        current_group_id = group_id(report['group'])
        ancestors = parent_chain(current_group_id, reports_by_id)
        report['ancestors'] = [
            {
                'groupid': group_id(ancestor['group']),
                'name': group_name(ancestor['group']),
            }
            for ancestor in ancestors
        ]

        effective = {}
        for collection_key in INHERITABLE_COLLECTIONS:
            results = []
            current_identities = set()

            # Build a lookup for identities present anywhere above this group.
            # Walk farthest-to-nearest so the source points to the original
            # ancestor rather than an intermediate parent that also inherited it.
            ancestor_sources = {}
            for distance in range(len(ancestors), 0, -1):
                ancestor = ancestors[distance - 1]
                ancestor_group_id = group_id(ancestor['group'])
                ancestor_group_name = group_name(ancestor['group'])
                for item in ancestor['policy'].get(collection_key) or []:
                    identity = item_identity(collection_key, item)
                    ancestor_sources.setdefault(identity, {
                        'source': 'inherited',
                        'sourceGroupId': ancestor_group_id,
                        'sourceGroupName': ancestor_group_name,
                        'distance': distance,
                    })

            # Use the current group's API representation for display, but mark
            # it inherited when its identity also exists in an ancestor.
            for item in report['policy'].get(collection_key) or []:
                identity = item_identity(collection_key, item)
                if identity in current_identities:
                    continue
                current_identities.add(identity)

                item_copy = dict(item) if isinstance(item, dict) else {'value': item}
                inherited_source = ancestor_sources.get(identity)
                if inherited_source:
                    item_copy['_reportMeta'] = dict(inherited_source)
                else:
                    item_copy['_reportMeta'] = {
                        'source': 'direct',
                        'sourceGroupId': current_group_id,
                        'sourceGroupName': group_name(report['group']),
                        'distance': 0,
                    }
                results.append(item_copy)

            # Retain ancestor assignments if a server version does not repeat
            # inherited objects in the child response. Prefer the nearest
            # ancestor's item representation while keeping the original source.
            appended_ancestor_identities = set()
            for ancestor in ancestors:
                for item in ancestor['policy'].get(collection_key) or []:
                    identity = item_identity(collection_key, item)
                    if identity in current_identities or identity in appended_ancestor_identities:
                        continue
                    appended_ancestor_identities.add(identity)
                    item_copy = dict(item) if isinstance(item, dict) else {'value': item}
                    item_copy['_reportMeta'] = dict(ancestor_sources[identity])
                    results.append(item_copy)

            effective[collection_key] = results

        report['effectivePolicy'] = effective


def build_navigation(group_reports):
    """Build a flattened, ordered hierarchy for the HTML policy group tree."""
    id_to_index = {}
    children = {}
    root_indexes = []

    for index, report in enumerate(group_reports):
        current_id = group_id(report['group'])
        if current_id:
            id_to_index[current_id] = index

    for index, report in enumerate(group_reports):
        parent_id = group_parent(report['group'])
        if parent_id == GLOBAL_POLICY_PARENT or parent_id not in id_to_index:
            root_indexes.append(index)
        else:
            children.setdefault(id_to_index[parent_id], []).append(index)

    def sort_key(index):
        group = group_reports[index]['group']
        name = group_name(group).strip()
        return (name.casefold(), name, group_id(group).casefold())

    root_indexes.sort(key=sort_key)
    for child_indexes in children.values():
        child_indexes.sort(key=sort_key)

    navigation = []
    visited = set()

    def walk(index, depth, ancestors):
        if index in visited:
            return
        visited.add(index)
        navigation.append({
            'index': index,
            'depth': depth,
            'ancestorIndexes': list(ancestors),
        })
        for child_index in children.get(index, []):
            walk(child_index, depth + 1, ancestors + [index])

    for root_index in root_indexes:
        walk(root_index, 0, [])

    # Include cycle/orphan leftovers rather than dropping them. Keep those
    # entries alphabetical as well so the tree remains predictable.
    for index in sorted(range(len(group_reports)), key=sort_key):
        if index not in visited:
            walk(index, 0, [])

    return navigation


def local_tag(tag):
    """Return an XML tag without a namespace."""
    return str(tag).split('}', 1)[-1]


def element_to_value(element):
    """Convert an XML element into a JSON-serializable value."""
    children = list(element)
    text_value = (element.text or '').strip()

    if not children and not element.attrib:
        return text_value

    result = {}
    for attr_name, attr_value in element.attrib.items():
        result[f'@{local_tag(attr_name)}'] = attr_value

    grouped = {}
    for child in children:
        grouped.setdefault(local_tag(child.tag), []).append(element_to_value(child))

    for key, values in grouped.items():
        result[key] = values[0] if len(values) == 1 else values

    if text_value:
        result['#text'] = text_value

    return result


def normalize_xml_token(value):
    """Normalize an XML tag or field name for resilient comparisons."""
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def looks_like_xml_wrapper(element):
    """Return True only for known XML collection wrapper elements.

    Record elements such as metarule can contain repeated criteria children.
    Those must remain one record and must not be mistaken for wrappers.
    """
    if not list(element):
        return False

    tag = normalize_xml_token(local_tag(element.tag))
    known_wrappers = {
        'files', 'filelist', 'hashes', 'hashlist',
        'metadata', 'metadatarules', 'metarules', 'metarulelist',
        'browserextensions', 'browserextensionlist', 'extensions', 'extensionlist',
        'paths', 'pathlist', 'blocklistpaths',
        'rules', 'rulelist', 'entries', 'entrylist',
        'records', 'recordlist', 'items', 'itemlist', 'results',
        'applications', 'baselines', 'blocklists', 'allowlists',
    }
    return tag in known_wrappers


def unwrap_record_elements(element):
    """Recursively unwrap known collection containers into record elements."""
    if not looks_like_xml_wrapper(element):
        return [element]

    records = []
    for child in list(element):
        records.extend(unwrap_record_elements(child))
    return records


def collect_normalized_keys(value, keys=None):
    """Collect normalized keys from a parsed XML value."""
    if keys is None:
        keys = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(normalize_xml_token(key))
            collect_normalized_keys(child, keys)
    elif isinstance(value, list):
        for child in value:
            collect_normalized_keys(child, keys)
    return keys


def xml_truthy(value):
    """Return True for common XML representations of an enabled setting."""
    if value is True:
        return True
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {
            '1', 'true', 'yes', 'y', 'on', 'enabled', 'enable',
            'elevate', 'elevated',
        }
    if isinstance(value, dict):
        return any(xml_truthy(child) for child in value.values())
    if isinstance(value, list):
        return any(xml_truthy(child) for child in value)
    return False


def has_elevation_control(value):
    """Detect an enabled Elevation Control setting in a metadata rule."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = normalize_xml_token(key)
            elevation_key = (
                normalized_key == 'integritylevel'
                or 'elevat' in normalized_key
                or normalized_key in {
                    'runasadmin', 'runasadministrator',
                    'administrativeprivileges', 'adminprivileges',
                }
            )
            if elevation_key and xml_truthy(child):
                return True
            if has_elevation_control(child):
                return True
    elif isinstance(value, list):
        return any(has_elevation_control(child) for child in value)
    return False


def classify_export_record(object_type, record_type, data):
    """Return a product-oriented category for an exported policy record."""
    object_type = str(object_type or '').lower()
    record_token = normalize_xml_token(record_type)
    keys = collect_normalized_keys(data)

    is_file = (
        record_token in {
            'file', 'files', 'hash', 'application', 'applicationfile',
            'allowlistfile', 'baselinefile', 'blocklistfile',
        }
        or bool(keys.intersection({'sha256', 'sha1', 'md5', 'hash', 'filehash'}))
    )
    is_metadata_rule = (
        record_token in {'metarule', 'metadatarule', 'metadata', 'rule'}
        or 'criteria' in keys
        or 'criterias' in keys
    )
    is_browser_extension = (
        'browserextension' in record_token
        or record_token in {'extension', 'browserplugin', 'plugin'}
        or bool(keys.intersection({
            'extensionid', 'browserextensionid', 'browserid',
            'extensionname', 'browserextension',
        }))
    )
    is_blocklist_path = (
        record_token in {'path', 'blocklistpath', 'pathrule'}
        or 'blocklistpath' in record_token
    )

    if object_type == 'allowlist':
        if is_browser_extension:
            return 'Browser Extensions'
        if is_metadata_rule:
            if has_elevation_control(data):
                return 'Elevation Control rules'
            return 'Allowlist Metadata Rules'
        if is_file:
            return 'File hashes'
        return 'Other records'

    if object_type == 'blocklist':
        if is_metadata_rule:
            return 'Blocklist Metadata Rules'
        if is_blocklist_path and not is_file:
            return 'Blocklist Paths'
        if is_file:
            return 'File hashes'
        return 'Other records'

    if object_type == 'baseline':
        if is_file or record_token:
            return 'File hashes'
        return 'Other records'

    if is_metadata_rule:
        return 'Metadata Rules'
    if is_browser_extension:
        return 'Browser Extensions'
    if is_blocklist_path and not is_file:
        return 'Paths'
    if is_file:
        return 'File hashes'
    return 'Other records'


def export_category_order(object_type, category_counts=None):
    """Return stable, product-oriented category ordering."""
    orders = {
        'allowlist': [
            'File hashes',
            'Allowlist Metadata Rules',
            'Elevation Control rules',
            'Browser Extensions',
            'Other records',
        ],
        'baseline': ['File hashes', 'Other records'],
        'blocklist': [
            'File hashes',
            'Blocklist Metadata Rules',
            'Blocklist Paths',
            'Other records',
        ],
    }
    order = list(orders.get(str(object_type or '').lower(), []))
    for category in (category_counts or {}):
        if category not in order:
            order.append(category)
    return order


def parse_export_xml(xml_text, object_type=''):
    """Parse exported XML into categorized records and counts."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {
            'records': [],
            'typeCounts': {},
            'categoryCounts': {},
            'categoryOrder': export_category_order(object_type),
            'parseError': str(exc),
            'rootName': '',
            'exportName': '',
        }

    results_section = None
    for element in root.iter():
        if normalize_xml_token(local_tag(element.tag)) == 'resultssection':
            results_section = element
            break

    # ElementTree elements with no children are falsey. Use an explicit None
    # check so an empty ResultsSection remains the selected container.
    container = results_section if results_section is not None else root
    candidate_elements = []
    for child in list(container):
        candidate_elements.extend(unwrap_record_elements(child))

    # Metadata fields can sit above ResultsSection in legacy export formats.
    # When no ResultsSection exists, avoid treating those fields as records.
    if results_section is None:
        metadata_tags = {
            'name', 'exportname', 'description', 'comment', 'version', 'id',
            'created', 'modified', 'timestamp',
        }
        candidate_elements = [
            element for element in candidate_elements
            if normalize_xml_token(local_tag(element.tag)) not in metadata_tags or list(element)
        ]

    records = []
    for element in candidate_elements:
        record_type = local_tag(element.tag)
        data = element_to_value(element)
        category = classify_export_record(object_type, record_type, data)
        records.append({
            '_recordType': record_type,
            '_category': category,
            '_elevationControl': category == 'Elevation Control rules',
            'data': data,
        })

    type_counts = dict(Counter(record['_recordType'] for record in records))
    category_counts = dict(Counter(record['_category'] for record in records))

    export_name = ''
    for element in list(root):
        if normalize_xml_token(local_tag(element.tag)) in {'name', 'exportname'}:
            export_name = (element.text or '').strip()
            break

    return {
        'records': records,
        'typeCounts': type_counts,
        'categoryCounts': category_counts,
        'categoryOrder': export_category_order(object_type, category_counts),
        'parseError': '',
        'rootName': local_tag(root.tag),
        'exportName': export_name,
    }


def unique_export_base(object_name, object_id, used_bases):
    """Return a collision-safe filename base while retaining readable names."""
    base = safe_filename(object_name)
    candidate = base
    if candidate.lower() in used_bases:
        candidate = f'{base}_{safe_filename(object_id)[:8]}'
        suffix = 2
        while candidate.lower() in used_bases:
            candidate = f'{base}_{safe_filename(object_id)[:8]}_{suffix}'
            suffix += 1
    used_bases.add(candidate.lower())
    return candidate


def build_export_html(object_type_label, object_name, object_id, generated_at, xml_filename, parsed):
    """Build a categorized, searchable HTML summary of one XML export."""
    data = {
        'typeLabel': object_type_label,
        'name': object_name,
        'id': object_id,
        'generatedAt': generated_at,
        'xmlFilename': xml_filename,
        'records': parsed['records'],
        'typeCounts': parsed['typeCounts'],
        'categoryCounts': parsed.get('categoryCounts', {}),
        'categoryOrder': parsed.get('categoryOrder', []),
        'parseError': parsed['parseError'],
        'rootName': parsed['rootName'],
    }

    template = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Airlock Digital policy object report</title>
<style>
:root{--navy:#081f33;--navy2:#103a54;--cyan:#60cde3;--blue:#1595ba;--ink:#172532;--muted:#687987;--line:#dce5ea;--bg:#f4f7f9;--white:#fff;--purple:#6d55aa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.45}
a{color:#087fa4}.header{padding:24px clamp(20px,4vw,52px);background:linear-gradient(120deg,var(--navy),var(--navy2));color:#fff}.eyebrow{color:var(--cyan);font-size:11px;font-weight:750;letter-spacing:.12em;text-transform:uppercase}.header h1{margin:7px 0 5px;font-size:clamp(25px,4vw,40px);overflow-wrap:anywhere}.meta{display:flex;flex-wrap:wrap;gap:8px 18px;color:rgba(255,255,255,.72);font-size:12px}.main{max-width:1500px;margin:0 auto;padding:24px clamp(16px,3vw,36px) 50px}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card,.panel{background:#fff;border:1px solid var(--line);border-radius:13px;box-shadow:0 6px 20px rgba(8,31,51,.05)}.card{padding:17px}.card .label{color:var(--muted);font-size:12px}.card .value{font-size:27px;font-weight:760;color:var(--navy);margin-top:4px}.toolbar{display:flex;gap:12px;align-items:center;margin:18px 0}.toolbar input{flex:1;padding:11px 13px;border:1px solid var(--line);border-radius:9px;font:inherit}.toolbar a{padding:10px 13px;border:1px solid var(--line);border-radius:9px;background:#fff;text-decoration:none;font-weight:650}.category-summary{display:flex;flex-wrap:wrap;gap:7px;margin:14px 0}.category-pill{background:#eaf2f6;border-radius:999px;padding:5px 9px;font-size:12px;color:#34566a}.category-pill.elevation{background:#efeafd;color:var(--purple);font-weight:700}.record-groups{display:grid;gap:16px}.panel{overflow:hidden}.panel[hidden]{display:none}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:16px 18px;border-bottom:1px solid var(--line)}.panel-title{font-weight:760}.panel-count{min-width:31px;padding:4px 9px;border-radius:999px;background:#e8f6fa;color:#087a9d;font-size:12px;font-weight:760;text-align:center}.panel.elevation .panel-head{border-left:5px solid var(--purple)}.records{display:grid;gap:9px;padding:16px}.record{border:1px solid #e3eaee;border-radius:10px;background:#fbfcfd;padding:13px}.record[hidden]{display:none}.record-title{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;font-weight:700}.record-heading{min-width:0;overflow-wrap:anywhere}.record-subtitle{margin-top:3px;color:var(--muted);font-size:11px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}.badges{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px}.badge{padding:3px 8px;border-radius:999px;background:#e7f6fa;color:#087a9d;font-size:11px;white-space:nowrap}.badge.element{background:#eef2f4;color:#596a76}.badge.elevation{background:#efeafd;color:var(--purple);font-weight:700}.grid{display:grid;grid-template-columns:minmax(170px,.7fr) minmax(0,2fr);gap:7px 14px;margin-top:10px}.key{color:var(--muted);font-size:11px;font-weight:700;overflow-wrap:anywhere}.value{overflow-wrap:anywhere;white-space:pre-wrap}.empty{padding:34px;text-align:center;color:var(--muted)}.error{padding:14px;border:1px solid #efcaca;background:#fff1f1;color:#9c3434;border-radius:9px;margin-bottom:14px}.no-match{display:none;padding:25px;border:1px dashed #cbd7dd;border-radius:11px;background:#fff;color:var(--muted);text-align:center}@media(max-width:720px){.cards{grid-template-columns:1fr}.toolbar{align-items:stretch;flex-direction:column}.toolbar input,.toolbar a{width:100%}.grid{grid-template-columns:1fr}.record-title{flex-direction:column}.badges{justify-content:flex-start}}@media print{.toolbar{display:none}.record{break-inside:avoid}.header{background:#fff;color:#000;padding-bottom:12px}.eyebrow,.meta{color:#555}.main{padding-top:10px}.card,.panel{box-shadow:none}}
</style>
</head>
<body>
<header class="header"><div class="eyebrow">Airlock Digital policy object</div><h1 id="title"></h1><div class="meta" id="meta"></div></header>
<main class="main"><div id="error"></div><div class="cards" id="cards"></div><div class="category-summary" id="categories"></div><div class="toolbar"><input id="filter" type="search" placeholder="Search formatted records"><a id="raw-link">Open raw XML</a></div><div id="records" class="record-groups"></div><div id="no-match" class="no-match">No formatted records match the search.</div></main>
<script>
const DATA=__EXPORT_DATA__;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cleanDisplay=v=>String(v??'').replace(/\\+/g,'\\');
const text=v=>v===null?'Null':v===true?'Enabled':v===false?'Disabled':typeof v==='object'?cleanDisplay(JSON.stringify(v)):cleanDisplay(v);
const singular={'File hashes':'file hash','Allowlist Metadata Rules':'Allowlist Metadata Rule','Elevation Control rules':'Elevation Control rule','Browser Extensions':'Browser Extension','Blocklist Metadata Rules':'Blocklist Metadata Rule','Blocklist Paths':'Blocklist Path','Other records':'other record'};
function countLabel(label,count){return Number(count).toLocaleString()+' '+(Number(count)===1?(singular[label]||label):label)}
function orderedCategories(){const result=[];for(const category of DATA.categoryOrder||[]){if(Number((DATA.categoryCounts||{})[category]||0)>0)result.push(category)}for(const category of Object.keys(DATA.categoryCounts||{})){if(!result.includes(category)&&Number(DATA.categoryCounts[category]||0)>0)result.push(category)}return result}
function flatten(value,prefix='',rows=[]){if(value&&typeof value==='object'&&!Array.isArray(value)){for(const [k,v] of Object.entries(value)){flatten(v,prefix?prefix+'.'+k:k,rows)}}else if(Array.isArray(value)){value.forEach((v,i)=>flatten(v,prefix+'['+i+']',rows))}else{rows.push([prefix,value])}return rows}
function field(value,names){if(!value||typeof value!=='object')return'';const wanted=new Set(names.map(v=>v.toLowerCase()));for(const [key,child] of Object.entries(value)){if(wanted.has(key.toLowerCase())&&child!==null&&typeof child!=='object'&&String(child).trim())return cleanDisplay(child);if(child&&typeof child==='object'){const nested=field(child,names);if(nested)return nested}}return''}
function recordLabel(record,index){const data=record.data;return field(data,['Name','Filename','OriginalFilename','Path','SHA256','SHA1','MD5','Hash','Publisher'])||record._recordType+' '+(index+1)}
function recordHtml(record,index){const rows=flatten(record.data),heading=recordLabel(record,index),secondary=field(record.data,['OriginalFilename','Filename','Path','SHA256','SHA1','MD5','Hash']),search=(record._category+' '+record._recordType+' '+JSON.stringify(record.data)).toLowerCase();return '<article class="record" data-search="'+esc(search)+'"><div class="record-title"><div class="record-heading">'+esc(heading)+(secondary&&secondary!==heading?'<div class="record-subtitle">'+esc(secondary)+'</div>':'')+'</div><div class="badges">'+(record._elevationControl?'<span class="badge elevation">Elevation Control</span>':'')+'<span class="badge element">'+esc(record._recordType)+'</span></div></div><div class="grid">'+rows.map(([k,v])=>'<div class="key">'+esc(k)+'</div><div class="value">'+esc(text(v))+'</div>').join('')+'</div></article>'}
document.getElementById('title').textContent=DATA.name;
document.getElementById('meta').innerHTML='<span>'+esc(DATA.typeLabel)+'</span><span>ID: <code>'+esc(DATA.id)+'</code></span><span>Generated: '+esc(DATA.generatedAt)+'</span>';
document.getElementById('raw-link').href=DATA.xmlFilename;
document.getElementById('cards').innerHTML='<div class="card"><div class="label">Total records</div><div class="value">'+DATA.records.length.toLocaleString()+'</div></div><div class="card"><div class="label">Record categories</div><div class="value">'+Object.keys(DATA.categoryCounts||{}).filter(k=>Number(DATA.categoryCounts[k])>0).length+'</div></div><div class="card"><div class="label">XML root</div><div class="value" style="font-size:18px">'+esc(DATA.rootName||'Unknown')+'</div></div>';
document.getElementById('categories').innerHTML=orderedCategories().map(category=>'<span class="category-pill '+(category==='Elevation Control rules'?'elevation':'')+'">'+esc(countLabel(category,DATA.categoryCounts[category]))+'</span>').join('');
if(DATA.parseError)document.getElementById('error').innerHTML='<div class="error">XML parsing failed: '+esc(DATA.parseError)+'</div>';
const recordsEl=document.getElementById('records'),noMatchEl=document.getElementById('no-match');
if(!DATA.records.length){recordsEl.innerHTML='<section class="panel"><div class="empty">This export contains no records in its XML ResultsSection.</div></section>';document.getElementById('filter').disabled=true}else{recordsEl.innerHTML=orderedCategories().map(category=>{const records=DATA.records.filter(record=>record._category===category);return '<section class="panel category-panel '+(category==='Elevation Control rules'?'elevation':'')+'" data-category="'+esc(category)+'"><div class="panel-head"><div class="panel-title">'+esc(category)+'</div><div class="panel-count">'+records.length.toLocaleString()+'</div></div><div class="records">'+records.map((record,index)=>recordHtml(record,index)).join('')+'</div></section>'}).join('')}
document.getElementById('filter').addEventListener('input',e=>{const n=e.target.value.trim().toLowerCase();let totalVisible=0;for(const panel of recordsEl.querySelectorAll('.category-panel')){let panelVisible=0;for(const record of panel.querySelectorAll('.record')){const match=!n||(record.dataset.search||'').includes(n);record.hidden=!match;if(match)panelVisible++}panel.hidden=!!n&&panelVisible===0;totalVisible+=panelVisible}noMatchEl.style.display=n&&totalVisible===0?'block':'none'});
</script>
</body>
</html>'''
    return template.replace('__EXPORT_DATA__', json_for_html_script(data))

def export_metadata_key(object_type, object_id):
    """Return a stable lookup key for exported-object metadata."""
    return f'{object_type}:{object_id}'


def build_html_report(server, generated_at, group_reports, navigation, export_metadata):
    """Build the self-contained browser-friendly HTML policy report."""
    html_groups = []
    for report in group_reports:
        stop_code = extract_stop_code(report['policy']) or {
            'path': 'stopcode',
            'enabled': False,
            'encoded': '',
        }
        html_groups.append({
            'group': report['group'],
            'policy': mask_stop_codes(report['policy']),
            'effectivePolicy': report.get('effectivePolicy', {}),
            'ancestors': report.get('ancestors', []),
            'enforcementAgentCount': report.get('enforcementAgentCount', 0),
            'mode': report.get('mode', {'key': 'unknown', 'label': 'Mode unknown'}),
            'stopCode': stop_code,
            'policyJsonHref': report.get('policyJsonHref', ''),
        })

    report_data = {
        'server': server,
        'generatedAt': generated_at,
        'groups': html_groups,
        'navigation': navigation,
        'objects': export_metadata,
    }

    template = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Airlock Digital policy report</title>
<style>
:root{--navy950:#071b2d;--navy900:#0b253b;--navy800:#123750;--blue600:#0d7ea2;--blue500:#12a3c7;--cyan300:#76d7e8;--green:#43a85c;--amber:#d99a28;--gray:#7d8b96;--ink900:#142230;--ink700:#3e5060;--ink500:#6d7e8c;--line:#dce5ea;--surface:#fff;--bg:#f4f7f9;--shadow:0 10px 30px rgba(7,27,45,.09);--radius:14px}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink900);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.45}button,input,select{font:inherit}button{cursor:pointer}a{color:var(--blue600)}
.app-header{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:74px;padding:14px 24px;background:linear-gradient(110deg,var(--navy950),var(--navy800));color:#fff;box-shadow:0 3px 18px rgba(7,27,45,.24)}.brand{display:flex;align-items:center;min-width:0}.brand-title{font-size:17px;font-weight:760}.brand-subtitle{color:rgba(255,255,255,.67);font-size:12px}.header-meta{text-align:right;font-size:12px;color:rgba(255,255,255,.75)}.header-meta strong{color:#fff}
.layout{display:grid;grid-template-columns:390px minmax(0,1fr);min-height:calc(100vh - 74px)}.sidebar{position:sticky;top:74px;align-self:start;height:calc(100vh - 74px);overflow:hidden;display:flex;flex-direction:column;background:#0a2135;color:#fff}.sidebar-head{padding:20px 18px 13px;border-bottom:1px solid rgba(255,255,255,.08)}.sidebar-label{margin-bottom:9px;color:rgba(255,255,255,.64);font-size:11px;font-weight:700;letter-spacing:.11em;text-transform:uppercase}.search-wrap{position:relative}.search-input{width:100%;padding:10px 12px;border:1px solid rgba(255,255,255,.14);border-radius:9px;outline:none;background:rgba(255,255,255,.08);color:#fff}.search-input::placeholder{color:rgba(255,255,255,.46)}.search-input:focus{border-color:var(--cyan300);box-shadow:0 0 0 3px rgba(118,215,232,.12)}.group-list{overflow:auto;padding:9px}.group-button{--depth:0;width:100%;position:relative;display:block;padding:9px 10px 9px calc(13px + var(--depth)*19px);border:0;border-radius:9px;background:transparent;color:rgba(255,255,255,.84);text-align:left}.group-button::before{content:"";position:absolute;left:calc(7px + var(--depth)*19px);top:19px;width:7px;border-top:1px dotted rgba(255,255,255,.38)}.group-button:hover{background:rgba(255,255,255,.07);color:#fff}.group-button.active{background:linear-gradient(100deg,rgba(18,163,199,.28),rgba(18,163,199,.11));color:#fff;box-shadow:inset 3px 0 0 var(--cyan300)}.group-line{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.group-name{font-weight:670;overflow-wrap:anywhere}.group-meta{display:flex;flex-wrap:wrap;gap:5px 9px;margin-top:4px;color:rgba(255,255,255,.56);font-size:10px}.mode-mini{display:inline-flex;align-items:center;gap:5px;font-weight:700}.mode-dot{width:8px;height:8px;border-radius:50%;background:var(--gray)}.mode-audit .mode-dot{background:var(--amber)}.mode-enforcement .mode-dot{background:var(--green)}.agent-mini{white-space:nowrap}.empty-filter{display:none;padding:24px 13px;color:rgba(255,255,255,.55);font-size:13px;text-align:center}
.main{min-width:0;padding:28px clamp(18px,3vw,44px) 54px}.mobile-picker{display:none;margin-bottom:18px}.mobile-picker select{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:9px;background:#fff}.report-hero{position:relative;overflow:hidden;padding:28px;border-radius:var(--radius);background:linear-gradient(125deg,#0d3149,#0c6381 72%,#0d7ea2);color:#fff;box-shadow:var(--shadow);border-left:7px solid var(--gray)}.report-hero.mode-audit{border-left-color:var(--amber)}.report-hero.mode-enforcement{border-left-color:var(--green)}.report-hero::after{content:"";position:absolute;width:260px;height:260px;right:-90px;top:-120px;border:45px solid rgba(118,215,232,.11);border-radius:50%}.eyebrow{margin-bottom:7px;color:var(--cyan300);font-size:11px;font-weight:760;letter-spacing:.12em;text-transform:uppercase}.hero-top{position:relative;z-index:1;display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.hero-title{margin:0;max-width:900px;font-size:clamp(25px,4vw,39px);line-height:1.1;overflow-wrap:anywhere}.mode-banner{display:inline-flex;align-items:center;gap:8px;padding:8px 11px;border:1px solid rgba(255,255,255,.25);border-radius:999px;background:rgba(255,255,255,.1);font-weight:750;white-space:nowrap}.mode-banner .mode-dot{width:11px;height:11px}.hero-meta{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:10px 18px;margin-top:14px;color:rgba(255,255,255,.75);font-size:13px}.hero-meta code{color:#fff}.breadcrumb{position:relative;z-index:1;margin-top:12px;color:rgba(255,255,255,.65);font-size:12px}
.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0 26px}.stat-card{padding:18px;border:1px solid var(--line);border-radius:12px;background:#fff;box-shadow:0 4px 18px rgba(7,27,45,.05)}.stat-label{color:var(--ink500);font-size:12px;font-weight:670}.stat-value{margin-top:5px;color:var(--navy900);font-size:27px;font-weight:760}.stat-detail{margin-top:2px;color:var(--ink500);font-size:11px}.stat-detail+.stat-detail{margin-top:1px}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:0 0 18px}.detail-search{flex:1;max-width:520px}.detail-search input{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:10px;outline:none;background:#fff}.print-button{padding:10px 14px;border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--navy900);font-weight:650}
.section{margin-top:19px;border:1px solid var(--line);border-radius:var(--radius);background:#fff;box-shadow:0 6px 22px rgba(7,27,45,.045);overflow:hidden}.section-header{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:18px 20px;border-bottom:1px solid var(--line)}.section-title{margin:0;color:var(--navy900);font-size:17px}.section-subtitle{margin-top:2px;color:var(--ink500);font-size:12px}.count-badge{min-width:31px;padding:4px 9px;border-radius:999px;background:#e8f6fa;color:var(--blue600);font-size:12px;font-weight:760;text-align:center}.section-body{padding:20px}.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 24px}.setting-row{min-width:0;padding:10px 0;border-bottom:1px solid #edf2f4}.setting-name{color:var(--ink500);font-size:11px;font-weight:720;letter-spacing:.03em;text-transform:uppercase}.setting-value{margin-top:4px;color:var(--ink900);overflow-wrap:anywhere}.setting-path{color:var(--ink500);font-size:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.value-badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:700}.value-true{background:#e8f6ec;color:#267a3b}.value-false{background:#eff2f4;color:#687783}.value-null{background:#eff2f4;color:#687783}.stop-code-value{display:inline-flex;align-items:center;gap:8px}.secret{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.12em}.secret-button{padding:4px 8px;border:1px solid #cbd7dd;border-radius:7px;background:#fff;color:var(--blue600);font-size:11px;font-weight:700}.setting-list{display:flex;flex-wrap:wrap;gap:6px}.setting-chip{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;background:#edf4f7;color:#34566a;font-size:11px}.setting-object-list{display:grid;gap:8px}.setting-object{padding:9px 10px;border:1px solid #e3eaee;border-radius:8px;background:#fbfcfd}.setting-object-title{margin-bottom:6px;color:var(--ink500);font-size:10px;font-weight:750;letter-spacing:.05em;text-transform:uppercase}.compact-grid{display:grid;grid-template-columns:minmax(120px,.7fr) minmax(0,2fr);gap:5px 10px}.compact-key{color:var(--ink500);font-size:10px;font-weight:700}.compact-value{min-width:0;overflow-wrap:anywhere}
.item-list{display:grid;gap:9px}.item-row{border:1px solid #e2e9ed;border-radius:10px;background:#fbfcfd}.item-row.inherited{border-left:4px solid #8b74c8;background:#fcfbff}.item-row[hidden]{display:none}.item-summary{display:grid;grid-template-columns:minmax(180px,1.2fr) minmax(160px,1fr) auto;gap:14px;align-items:center;padding:13px 15px}.item-primary{min-width:0;font-weight:660;overflow-wrap:anywhere}.item-secondary{min-width:0;color:var(--ink500);font-size:12px;overflow-wrap:anywhere}.item-id{display:block;margin-top:3px;color:#85939e;font:10px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.item-badges{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px}.tag{display:inline-flex;align-items:center;padding:3px 7px;border-radius:999px;font-size:10px;font-weight:750}.tag-direct{background:#e8f6fa;color:#087a9d}.tag-inherited{background:#efeafd;color:#634ea0}.tag-records{background:#eef2f4;color:#51626f}.tag-category{background:#eaf2f6;color:#34566a;font-weight:650}.tag-elevation{background:#efeafd;color:#634ea0;font-weight:760}.item-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:9px}.item-actions a{padding:5px 8px;border:1px solid #d4e0e6;border-radius:7px;background:#fff;text-decoration:none;font-size:11px;font-weight:680}.item-details{padding:0 15px 14px}details>summary{cursor:pointer;color:var(--blue600);font-size:12px;font-weight:650}.json-grid{margin-top:10px;display:grid;gap:7px}.json-row{display:grid;grid-template-columns:minmax(135px,.75fr) minmax(0,2fr);gap:12px;padding:7px 0;border-bottom:1px solid #edf2f4}.json-key{color:var(--ink500);font-size:11px;font-weight:680;overflow-wrap:anywhere}.json-value{min-width:0;overflow-wrap:anywhere;white-space:pre-wrap}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}pre{max-height:520px;overflow:auto;margin:12px 0 0;padding:15px;border-radius:9px;background:#071b2d;color:#d7eef3;font-size:11px;line-height:1.55}.empty-state{padding:22px;border:1px dashed #cbd7dd;border-radius:10px;color:var(--ink500);text-align:center}.no-match{display:none;margin-top:16px;padding:16px;border:1px dashed #cbd7dd;border-radius:9px;color:var(--ink500);text-align:center}.raw-links{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:12px}.raw-links a{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:#fff;text-decoration:none;font-size:12px;font-weight:650}
@media(max-width:1050px){.layout{grid-template-columns:320px minmax(0,1fr)}.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.item-summary{grid-template-columns:1fr}.item-badges{justify-content:flex-start}}
@media(max-width:760px){.layout{display:block}.sidebar{display:none}.mobile-picker{display:block}.main{padding-top:18px}.app-header{position:static}.summary-grid{grid-template-columns:1fr 1fr}.settings-grid{grid-template-columns:1fr}.hero-top{flex-direction:column}.mode-banner{white-space:normal}.toolbar{align-items:stretch;flex-direction:column}.detail-search{max-width:none}.print-button{width:100%}.json-row{grid-template-columns:1fr}.header-meta{display:none}}
@media(max-width:480px){.summary-grid{grid-template-columns:1fr}.app-header{padding:12px 16px}.report-hero{padding:22px}.section-body{padding:15px}}
@media print{.app-header,.sidebar,.mobile-picker,.toolbar{display:none}.layout{display:block}.main{padding:0}.report-hero{box-shadow:none}.section,.stat-card{box-shadow:none;break-inside:avoid}.item-details details:not([open]){display:none}}
</style>
</head>
<body>
<header class="app-header"><div class="brand"><div><div class="brand-title">Airlock Digital</div><div class="brand-subtitle">Offline policy snapshot</div></div></div><div class="header-meta">Server <strong id="server-name"></strong><br><span id="generated-at"></span></div></header>
<div class="layout"><aside class="sidebar"><div class="sidebar-head"><div class="sidebar-label">Policy groups</div><div class="search-wrap"><input id="group-search" class="search-input" type="search" placeholder="Search policy groups"></div></div><div id="group-list" class="group-list"></div><div id="empty-filter" class="empty-filter">No matching policy groups.</div></aside><main class="main"><div class="mobile-picker"><select id="mobile-select"></select></div><div id="content"></div></main></div>
<script>
const REPORT=__REPORT_DATA__;
const COLLECTION_LABELS={applications:'Allowlists',baselines:'Baselines',blocklists:'Blocklists',paths:'Paths',publishers:'Publishers',pprocesses:'Parent processes',gprocesses:'Grandparent processes'};
const KNOWN_COLLECTIONS=new Set(Object.keys(COLLECTION_LABELS));
const CATEGORY_ORDER=['File hashes','Allowlist Metadata Rules','Elevation Control rules','Browser Extensions','Blocklist Metadata Rules','Blocklist Paths','Other records'];
const CATEGORY_SINGULAR={'File hashes':'file hash','Allowlist Metadata Rules':'Allowlist Metadata Rule','Elevation Control rules':'Elevation Control rule','Browser Extensions':'Browser Extension','Blocklist Metadata Rules':'Blocklist Metadata Rule','Blocklist Paths':'Blocklist Path','Other records':'other record'};
const state={selectedIndex:REPORT.navigation.length?REPORT.navigation[0].index:0,detailFilter:''};
const contentEl=document.getElementById('content'),groupListEl=document.getElementById('group-list'),groupSearchEl=document.getElementById('group-search'),mobileSelectEl=document.getElementById('mobile-select'),emptyFilterEl=document.getElementById('empty-filter');
document.getElementById('server-name').textContent=REPORT.server;document.getElementById('generated-at').textContent=REPORT.generatedAt;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const groupId=g=>String(g.groupid||g.id||'');
const groupName=(g,i)=>String(g.name||g.groupname||groupId(g)||('Policy group '+(i+1)));
const humanize=k=>String(k).replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
function categoryCountLabel(label,count){return Number(count).toLocaleString()+' '+(Number(count)===1?(CATEGORY_SINGULAR[label]||label):label)}
function orderedCategoryEntries(counts){const entries=[];for(const category of CATEGORY_ORDER){if(Number((counts||{})[category]||0)>0)entries.push([category,Number(counts[category])])}for(const [category,count] of Object.entries(counts||{})){if(!CATEGORY_ORDER.includes(category)&&Number(count)>0)entries.push([category,Number(count)])}return entries}
function categoryBreakdown(counts){return orderedCategoryEntries(counts).map(([category,count])=>categoryCountLabel(category,count)).join(' · ')}
function categoryTags(counts){return orderedCategoryEntries(counts).map(([category,count])=>'<span class="tag tag-category '+(category==='Elevation Control rules'?'tag-elevation':'')+'">'+esc(categoryCountLabel(category,count))+'</span>').join('')}
function addCounts(target,source){for(const [key,value] of Object.entries(source||{}))target[key]=(target[key]||0)+Number(value||0);return target}
function modeClass(mode){return 'mode-'+((mode&&mode.key)||'unknown')}
function scalarValueHtml(v){if(v===true)return '<span class="value-badge value-true">Enabled</span>';if(v===false)return '<span class="value-badge value-false">Disabled</span>';if(v===null||v===undefined||v==='')return '<span class="value-badge value-null">Not set</span>';return esc(v)}
function valueHtml(v){
 if(Array.isArray(v)){
  if(!v.length)return '<span class="value-badge value-null">Not set</span>';
  if(v.every(item=>item===null||typeof item!=='object'))return '<div class="setting-list">'+v.map(item=>'<span class="setting-chip">'+scalarValueHtml(item)+'</span>').join('')+'</div>';
  return '<div class="setting-object-list">'+v.map((item,index)=>{if(!item||typeof item!=='object')return '<div class="setting-object">'+scalarValueHtml(item)+'</div>';return '<div class="setting-object"><div class="setting-object-title">Entry '+(index+1)+'</div><div class="compact-grid">'+Object.entries(item).map(([k,val])=>'<div class="compact-key">'+esc(humanize(k))+'</div><div class="compact-value">'+(val&&typeof val==='object'?'<pre>'+esc(JSON.stringify(val,null,2))+'</pre>':scalarValueHtml(val))+'</div>').join('')+'</div></div>'}).join('')+'</div>';
 }
 if(v&&typeof v==='object')return '<pre>'+esc(JSON.stringify(v,null,2))+'</pre>';
 return scalarValueHtml(v)
}
function settingRows(value,prefix='',rows=[]){if(value&&typeof value==='object'&&!Array.isArray(value)){for(const [key,child] of Object.entries(value)){if(KNOWN_COLLECTIONS.has(key))continue;const path=prefix?prefix+'.'+key:key;if(child&&typeof child==='object'&&!Array.isArray(child))settingRows(child,path,rows);else rows.push({key:path,value:child})}}return rows}
function settingLabel(path){const raw=path.split('.').pop(),normalized=String(raw).toLowerCase().replace(/[^a-z0-9]/g,'');if(normalized==='customotp')return 'Custom OTP';if(normalized==='targetvers')return 'Target versions';return humanize(raw)}
function itemName(item,fallback){return item.name||item.displayname||item.filename||item.path||item.value||fallback}
function displayItemName(collectionKey,item,fallback){const value=itemName(item,fallback);return collectionKey==='paths'?String(value).replace(/\\+/g,'\\'):value}
function itemId(item){return item.applicationid||item.baselineid||item.blocklistid||item.id||''}
function itemComment(item){return item.comment||item.description||item.processType||''}
function cleanItem(item){const copy={...item};delete copy._reportMeta;return copy}
function itemSearch(item){return JSON.stringify(cleanItem(item)).toLowerCase()}
function objectInfo(collectionKey,item){const cfg={applications:['allowlist','applicationid'],baselines:['baseline','baselineid'],blocklists:['blocklist','blocklistid']}[collectionKey];if(!cfg)return null;const id=item[cfg[1]];return id?REPORT.objects[cfg[0]+':'+id]||null:null}
function collectionStats(items,collectionKey){let records=0,direct=0,inherited=0,directRecords=0,inheritedRecords=0;const categoryCounts={};for(const item of items){const inheritedItem=!!(item._reportMeta&&item._reportMeta.source==='inherited'),info=objectInfo(collectionKey,item),recordCount=info?Number(info.recordCount||0):0;if(inheritedItem){inherited++;inheritedRecords+=recordCount}else{direct++;directRecords+=recordCount}records+=recordCount;if(info)addCounts(categoryCounts,info.categoryCounts)}return{records,direct,inherited,directRecords,inheritedRecords,categoryCounts}}
function collectionSection(title,subtitle,items,collectionKey,typeLabel){
 const stats=collectionStats(items,collectionKey),recordBacked=['applications','baselines','blocklists'].includes(collectionKey),types=recordBacked?categoryBreakdown(stats.categoryCounts):'';
 const rows=items.map((item,index)=>{const meta=item._reportMeta||{source:'direct'},inherited=meta.source==='inherited',info=objectInfo(collectionKey,item),id=itemId(item),name=displayItemName(collectionKey,item,typeLabel+' '+(index+1)),comment=itemComment(item);const sourceTag=inherited?'<span class="tag tag-inherited">Inherited from '+esc(meta.sourceGroupName||'parent')+'</span>':'<span class="tag tag-direct">Direct</span>';const recordTag=info?'<span class="tag tag-records">'+Number(info.recordCount||0).toLocaleString()+' records</span>':'';const typeTags=info?categoryTags(info.categoryCounts):'';const actions=info?'<div class="item-actions"><a href="'+esc(info.htmlHref)+'">View formatted records</a><a href="'+esc(info.xmlHref)+'">Open raw XML</a></div>':'';const searchText=itemSearch(item)+' '+(meta.sourceGroupName||'').toLowerCase()+' '+(info?categoryBreakdown(info.categoryCounts).toLowerCase():'');return '<article class="item-row searchable-item '+(inherited?'inherited':'')+'" data-search="'+esc(searchText)+'"><div class="item-summary"><div class="item-primary">'+esc(name)+(id?'<span class="item-id">'+esc(id)+'</span>':'')+actions+'</div><div class="item-secondary">'+esc(comment||'No comment')+'</div><div class="item-badges">'+sourceTag+recordTag+typeTags+'</div></div></article>'}).join('');
 const breakdown=recordBacked?' Direct: '+stats.direct.toLocaleString()+'. Inherited: '+stats.inherited.toLocaleString()+'. Records: '+stats.directRecords.toLocaleString()+' direct, '+stats.inheritedRecords.toLocaleString()+' inherited.'+(types?' Types: '+types+'.':''):' Direct: '+stats.direct.toLocaleString()+'. Inherited: '+stats.inherited.toLocaleString()+'.';
 return '<section class="section searchable-section"><div class="section-header"><div><h2 class="section-title">'+esc(title)+'</h2><div class="section-subtitle">'+esc(subtitle)+breakdown+'</div></div><span class="count-badge">'+items.length.toLocaleString()+'</span></div><div class="section-body">'+(rows?'<div class="item-list">'+rows+'</div><div class="no-match">No entries in this section match the filter.</div>':'<div class="empty-state">No direct or inherited entries apply.</div>')+'</div></section>'
}
function stopCodeRow(reportGroup){const s=reportGroup.stopCode||{enabled:false,path:'stopcode'};if(!s.enabled)return '<div class="setting-row searchable-item" data-search="stop code disabled"><div class="setting-name">Stop Code</div><div class="setting-path">'+esc(s.path||'stopcode')+'</div><div class="setting-value"><span class="value-badge value-false">Disabled</span></div></div>';return '<div class="setting-row searchable-item" data-search="stop code enabled"><div class="setting-name">Stop Code</div><div class="setting-path">'+esc(s.path||'stopcode')+'</div><div class="setting-value stop-code-value"><span class="value-badge value-true">Enabled</span><span class="secret" id="stop-secret">••••••••</span><button class="secret-button" id="stop-toggle" type="button">Show</button></div></div>'}
function settingsSection(reportGroup){const rows=settingRows(reportGroup.policy).filter(r=>!r.key.toLowerCase().replace(/[^a-z0-9]/g,'').endsWith('stopcode'));const content=stopCodeRow(reportGroup)+rows.map(r=>'<div class="setting-row searchable-item" data-search="'+esc((r.key+' '+JSON.stringify(r.value)).toLowerCase())+'"><div class="setting-name">'+esc(settingLabel(r.key))+'</div><div class="setting-path">'+esc(r.key)+'</div><div class="setting-value">'+valueHtml(r.value)+'</div></div>').join('');return '<section class="section searchable-section"><div class="section-header"><div><h2 class="section-title">Policy settings</h2><div class="section-subtitle">Settings returned directly for this policy group. Policy settings are not inherited.</div></div><span class="count-badge">'+(rows.length+1)+'</span></div><div class="section-body"><div class="settings-grid">'+content+'</div><div class="no-match">No settings match the filter.</div></div></section>'}
function decodeB64Utf8(value){try{const bytes=Uint8Array.from(atob(value),c=>c.charCodeAt(0));return new TextDecoder().decode(bytes)}catch(_){return ''}}
function rawSection(reportGroup){return '<section class="section"><div class="section-header"><div><h2 class="section-title">Raw policy data</h2><div class="section-subtitle">The inline preview masks Stop Code. The saved JSON file contains the complete API response.</div></div></div><div class="section-body"><div class="raw-links">'+(reportGroup.policyJsonHref?'<a href="'+esc(reportGroup.policyJsonHref)+'">Open raw policy JSON</a>':'')+'</div><details><summary>Show masked JSON preview</summary><pre>'+esc(JSON.stringify(reportGroup.policy,null,2))+'</pre></details></div></section>'}
function statCard(label,value,details=[]){const lines=(Array.isArray(details)?details:[details]).filter(Boolean);return '<div class="stat-card"><div class="stat-label">'+esc(label)+'</div><div class="stat-value">'+esc(value)+'</div>'+lines.map(line=>'<div class="stat-detail">'+esc(line)+'</div>').join('')+'</div>'}
function effective(reportGroup,key){return (reportGroup.effectivePolicy&&reportGroup.effectivePolicy[key])||[]}
function assignmentSummary(reportGroup,key){const items=effective(reportGroup,key),stats=collectionStats(items,key);return{assignments:items.length,records:stats.records,direct:stats.direct,inherited:stats.inherited,directRecords:stats.directRecords,inheritedRecords:stats.inheritedRecords,categoryCounts:stats.categoryCounts}}
function renderReport(){
 const rg=REPORT.groups[state.selectedIndex];if(!rg){contentEl.innerHTML='<div class="empty-state">No policy groups were returned.</div>';return}
 const g=rg.group||{},name=groupName(g,state.selectedIndex),id=groupId(g),mode=rg.mode||{key:'unknown',label:'Mode unknown'},apps=assignmentSummary(rg,'applications'),bases=assignmentSummary(rg,'baselines'),blocks=assignmentSummary(rg,'blocklists'),paths=effective(rg,'paths'),pubs=effective(rg,'publishers'),parents=effective(rg,'pprocesses').map(i=>({...i,processType:'Parent process'})),grands=effective(rg,'gprocesses').map(i=>({...i,processType:'Grandparent process'})),processes=parents.concat(grands),breadcrumb=(rg.ancestors||[]).slice().reverse().map(a=>a.name).concat([name]).join(' › ');
 const assignmentCard=(label,summary)=>{const details=['Direct: '+summary.direct.toLocaleString()+' · Inherited: '+summary.inherited.toLocaleString(),'Records: '+summary.directRecords.toLocaleString()+' direct · '+summary.inheritedRecords.toLocaleString()+' inherited'];const types=categoryBreakdown(summary.categoryCounts);if(types)details.push('Types: '+types);return statCard(label,summary.assignments.toLocaleString(),details)};
 contentEl.innerHTML='<section class="report-hero '+modeClass(mode)+'"><div class="eyebrow">Selected policy group</div><div class="hero-top"><h1 class="hero-title">'+esc(name)+'</h1><div class="mode-banner '+modeClass(mode)+'"><span class="mode-dot"></span>'+esc(mode.label)+'</div></div><div class="hero-meta"><span>Enforcement Agents: <strong>'+Number(rg.enforcementAgentCount||0).toLocaleString()+'</strong></span><span>Server: <strong>'+esc(REPORT.server)+'</strong></span>'+(id?'<span>Group ID: <code>'+esc(id)+'</code></span>':'')+'<span>Generated: '+esc(REPORT.generatedAt)+'</span></div><div class="breadcrumb">'+esc(breadcrumb)+'</div></section><div class="summary-grid">'+statCard('Enforcement Agents',Number(rg.enforcementAgentCount||0).toLocaleString(),'Enforcement Agents currently in this Policy Group')+assignmentCard('Allowlists',apps)+assignmentCard('Baselines',bases)+assignmentCard('Blocklists',blocks)+'</div><div class="toolbar"><div class="detail-search"><input id="detail-filter" type="search" placeholder="Filter effective policy entries and settings" value="'+esc(state.detailFilter)+'"></div><button class="print-button" type="button" onclick="window.print()">Print report</button></div>'+collectionSection('Allowlists','Effective allowlists applied to this policy group.',effective(rg,'applications'),'applications','Allowlist')+collectionSection('Baselines','Effective baselines applied to this policy group.',effective(rg,'baselines'),'baselines','Baseline')+collectionSection('Blocklists','Effective blocklists applied to this policy group.',effective(rg,'blocklists'),'blocklists','Blocklist')+collectionSection('Paths','Effective trusted path rules applied to this policy group.',paths,'paths','Path')+collectionSection('Publishers','Effective trusted publisher rules applied to this policy group.',pubs,'publishers','Publisher')+collectionSection('Parent and grandparent processes','Effective process rules applied to this policy group.',processes,'processes','Process')+rawSection(rg)+settingsSection(rg);
 document.getElementById('detail-filter').addEventListener('input',e=>{state.detailFilter=e.target.value;applyDetailFilter()});const toggle=document.getElementById('stop-toggle');if(toggle){let shown=false;toggle.addEventListener('click',()=>{shown=!shown;document.getElementById('stop-secret').textContent=shown?decodeB64Utf8(rg.stopCode.encoded):'••••••••';toggle.textContent=shown?'Hide':'Show'})}applyDetailFilter();syncControls()
}
function applyDetailFilter(){const n=state.detailFilter.trim().toLowerCase();for(const section of document.querySelectorAll('.searchable-section')){const items=[...section.querySelectorAll('.searchable-item')];let visible=0;for(const item of items){const match=!n||(item.dataset.search||'').includes(n);item.hidden=!match;if(match)visible++}const no=section.querySelector('.no-match');if(no)no.style.display=n&&items.length&&visible===0?'block':'none'}}
function selectGroup(index){state.selectedIndex=Number(index);state.detailFilter='';renderReport();window.scrollTo({top:0,behavior:'smooth'})}
function agentCountLabel(count){const n=Number(count||0);return n.toLocaleString()+' Enforcement Agent'+(n===1?'':'s')}
function renderNavigation(){groupListEl.innerHTML=REPORT.navigation.map(nav=>{const rg=REPORT.groups[nav.index],g=rg.group||{},mode=rg.mode||{key:'unknown',label:'Mode unknown'};return '<button type="button" class="group-button" style="--depth:'+nav.depth+'" data-index="'+nav.index+'" data-ancestors="'+esc(nav.ancestorIndexes.join(','))+'" data-name="'+esc(groupName(g,nav.index).toLowerCase())+'"><div class="group-line"><span class="group-name">'+esc(groupName(g,nav.index))+'</span></div><div class="group-meta"><span class="mode-mini '+modeClass(mode)+'"><span class="mode-dot"></span>'+esc(mode.label)+'</span><span class="agent-mini">'+agentCountLabel(rg.enforcementAgentCount)+'</span></div></button>'}).join('');mobileSelectEl.innerHTML=REPORT.navigation.map(nav=>{const rg=REPORT.groups[nav.index],indent='  '.repeat(nav.depth);return '<option value="'+nav.index+'">'+indent+esc(groupName(rg.group||{},nav.index))+' · '+esc((rg.mode||{}).label||'Mode unknown')+' · '+esc(agentCountLabel(rg.enforcementAgentCount))+'</option>'}).join('');groupListEl.addEventListener('click',e=>{const b=e.target.closest('.group-button');if(b)selectGroup(b.dataset.index)});mobileSelectEl.addEventListener('change',e=>selectGroup(e.target.value))}
function syncControls(){for(const b of groupListEl.querySelectorAll('.group-button'))b.classList.toggle('active',Number(b.dataset.index)===state.selectedIndex);mobileSelectEl.value=String(state.selectedIndex)}
groupSearchEl.addEventListener('input',e=>{const n=e.target.value.trim().toLowerCase(),buttons=[...groupListEl.querySelectorAll('.group-button')],show=new Set();if(!n){buttons.forEach(b=>show.add(Number(b.dataset.index)))}else{for(const b of buttons){if((b.dataset.name||'').includes(n)||b.textContent.toLowerCase().includes(n)){show.add(Number(b.dataset.index));for(const a of (b.dataset.ancestors||'').split(',').filter(Boolean))show.add(Number(a))}}}for(const b of buttons)b.style.display=show.has(Number(b.dataset.index))?'block':'none';emptyFilterEl.style.display=show.size?'none':'block'});
renderNavigation();renderReport();
</script>
</body>
</html>'''
    return template.replace('__REPORT_DATA__', json_for_html_script(report_data))


def main():
    parser = argparse.ArgumentParser(
        description='Dump Airlock policy groups, policies, Enforcement Agent counts, and referenced allowlists, baselines, and blocklists.'
    )
    parser.add_argument(
        '--server',
        required=True,
        help='Airlock server hostname, without https:// or port',
    )
    parser.add_argument('--api-key', required=True, help='Airlock API key')
    parser.add_argument('--version', action='version', version=SCRIPT_VERSION)
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Disable SSL certificate verification (NOT for production)',
    )
    args = parser.parse_args()

    verify_ssl = not args.insecure
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sys.stderr.write(
            '\n\033[91m'
            '!!! INSECURE MODE ENABLED !!!\n'
            'SSL certificate verification is DISABLED.\n\n'
            'This means:\n'
            '  • Your connection is not secure.\n'
            '  • An attacker on the network could intercept or modify traffic.\n'
            '  • Use this option only in a trusted lab environment.\n'
            '\033[0m\n'
        )

    server_alias = get_server_alias(args.server)
    timestamp = get_timestamp()
    generated_at = get_display_timestamp()
    output_dir = f'airlock_policy_export_{server_alias}_{timestamp}'
    policies_dir = os.path.join(output_dir, 'policies')
    allowlists_dir = os.path.join(output_dir, 'allowlists')
    baselines_dir = os.path.join(output_dir, 'baselines')
    blocklists_dir = os.path.join(output_dir, 'blocklists')

    for folder in (output_dir, policies_dir, allowlists_dir, baselines_dir, blocklists_dir):
        os.makedirs(folder, exist_ok=True)

    print()
    print('Airlock policy export')
    print('---------------------------')
    print(f'Script build: {SCRIPT_VERSION}')
    print(f'Server: {args.server}')
    print('Port: 3129')
    print(f"API key: ending in '{args.api_key[-4:]}'")
    print(f'Output dir: {output_dir}')
    print('Folders:')
    print('  policies/')
    print('  allowlists/')
    print('  baselines/')
    print('  blocklists/')
    print()

    print('[1/5] Downloading policy group list...')
    response = post(args.server, args.api_key, '/v1/group', verify_ssl=verify_ssl)
    groups_json = response.json()
    groups_path = os.path.join(output_dir, 'policy_group_list.json')
    save_json(groups_path, groups_json)
    groups = as_list(groups_json)
    print(f'  Saved: {groups_path}')
    print(f'  Groups found: {len(groups)}')
    print()

    print('[2/5] Downloading agent list for Enforcement Agent counts...')
    response = post(args.server, args.api_key, '/v1/agent/find', verify_ssl=verify_ssl)
    agents_json = response.json()
    agents_path = os.path.join(output_dir, 'agent_list.json')
    save_json(agents_path, agents_json)
    agents = as_list(agents_json)
    agent_counts = count_agents_by_group(agents)
    print(f'  Saved: {agents_path}')
    print(f'  Enforcement Agents found: {len(agents)}')
    print()

    print('[3/5] Downloading policy group details...')
    all_export_refs = {'allowlist': {}, 'baseline': {}, 'blocklist': {}}
    group_reports = []

    for group_number, group in enumerate(groups, start=1):
        current_group_id = group_id(group)
        current_group_name = group_name(group)

        if not current_group_id:
            print(f'  Group {group_number} of {len(groups)}: skipping group with no groupid/id.')
            print()
            continue

        safe_group_name = safe_filename(current_group_name)
        group_output_dir = os.path.join(policies_dir, safe_group_name)
        os.makedirs(group_output_dir, exist_ok=True)

        print(f'  Group {group_number} of {len(groups)}: {current_group_name} ({current_group_id})')

        response = post(
            args.server,
            args.api_key,
            '/v1/group/policies',
            params={'groupid': current_group_id},
            verify_ssl=verify_ssl,
        )
        policy_json = response.json()
        policy_body = get_policy_body(policy_json)

        json_filename = f'{safe_group_name}_policies.json'
        json_path = os.path.join(group_output_dir, json_filename)
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
        save_text(
            processes_xml_path,
            build_processes_xml(policy_body.get('pprocesses'), policy_body.get('gprocesses')),
        )
        save_text(paths_txt_path, build_simple_name_txt(policy_body.get('paths'), normalize_paths=True))
        save_text(publishers_txt_path, build_simple_name_txt(policy_body.get('publishers')))
        save_text(
            processes_txt_path,
            build_processes_txt(policy_body.get('pprocesses'), policy_body.get('gprocesses')),
        )
        save_name_list(allowlists_txt_path, policy_body.get('applications'))
        save_name_list(baselines_txt_path, policy_body.get('baselines'))
        save_name_list(blocklists_txt_path, policy_body.get('blocklists'))

        merge_refs(all_export_refs, find_export_references(policy_json))

        report = {
            'group': group,
            'policy': policy_body,
            'enforcementAgentCount': agent_counts.get(current_group_id, 0),
            'mode': policy_mode(policy_body),
            'policyJsonHref': os.path.relpath(json_path, output_dir).replace(os.sep, '/'),
        }
        group_reports.append(report)

        print(f'    Enforcement Agents: {report["enforcementAgentCount"]}')
        print(f'    Mode: {report["mode"]["label"]}')
        print(f'    Saved: {json_path}')
        print(f'    Saved: {paths_xml_path}')
        print(f'    Saved: {publishers_xml_path}')
        print(f'    Saved: {processes_xml_path}')
        print(f'    Saved: {paths_txt_path}')
        print(f'    Saved: {publishers_txt_path}')
        print(f'    Saved: {processes_txt_path}')
        print(f'    Saved: {allowlists_txt_path}')
        print(f'    Saved: {baselines_txt_path}')
        print(f'    Saved: {blocklists_txt_path}')
        print()

    build_effective_policies(group_reports)
    navigation = build_navigation(group_reports)

    print('  Completed policy group export.')
    print()
    print('  Unique referenced policy objects found:')
    print(f'    Allowlists: {len(all_export_refs["allowlist"])}')
    print(f'    Baselines: {len(all_export_refs["baseline"])}')
    print(f'    Blocklists: {len(all_export_refs["blocklist"])}')
    print()

    print('[4/5] Exporting referenced allowlists, baselines, and blocklists with HTML summaries...')
    export_config = {
        'allowlist': {
            'endpoint': '/v1/application/export',
            'id_param': 'applicationid',
            'folder': allowlists_dir,
            'folder_name': 'allowlists',
            'label': 'Allowlist',
        },
        'baseline': {
            'endpoint': '/v1/baseline/export',
            'id_param': 'baselineid',
            'folder': baselines_dir,
            'folder_name': 'baselines',
            'label': 'Baseline',
        },
        'blocklist': {
            'endpoint': '/v1/blocklist/export',
            'id_param': 'blocklistid',
            'folder': blocklists_dir,
            'folder_name': 'blocklists',
            'label': 'Blocklist',
        },
    }
    export_metadata = {}

    for object_type, objects in all_export_refs.items():
        config = export_config[object_type]
        total_objects = len(objects)
        used_bases = set()
        print(f'  {config["label"]}s: {total_objects}')

        for object_number, (object_id, object_name) in enumerate(objects.items(), start=1):
            print(
                f'    {config["label"]} {object_number} of {total_objects}: '
                f'{object_name} ({object_id})'
            )
            response = post(
                args.server,
                args.api_key,
                config['endpoint'],
                params={config['id_param']: object_id},
                verify_ssl=verify_ssl,
            )
            xml_text = response.text
            base = unique_export_base(object_name, object_id, used_bases)
            xml_filename = f'{base}.xml'
            html_filename = f'{base}.html'
            xml_path = os.path.join(config['folder'], xml_filename)
            html_path = os.path.join(config['folder'], html_filename)
            save_text(xml_path, xml_text)

            parsed = parse_export_xml(xml_text, object_type)
            object_html = build_export_html(
                config['label'],
                object_name,
                object_id,
                generated_at,
                xml_filename,
                parsed,
            )
            save_text(html_path, object_html)

            metadata = {
                'objectType': object_type,
                'name': object_name,
                'id': object_id,
                'recordCount': len(parsed['records']),
                'typeCounts': parsed['typeCounts'],
                'categoryCounts': parsed.get('categoryCounts', {}),
                'categoryOrder': parsed.get('categoryOrder', []),
                'xmlHref': f'{config["folder_name"]}/{xml_filename}',
                'htmlHref': f'{config["folder_name"]}/{html_filename}',
                'parseError': parsed['parseError'],
            }
            export_metadata[export_metadata_key(object_type, object_id)] = metadata

            print(f'      Records: {metadata["recordCount"]}')
            if parsed['parseError']:
                print(f'      WARNING: XML could not be parsed: {parsed["parseError"]}')
            print(f'      Saved: {xml_path}')
            print(f'      Saved: {html_path}')

        print()

    print('[5/5] Generating human-readable HTML policy report...')
    html_report_path = os.path.join(output_dir, 'policy_report.html')
    html_report = build_html_report(
        server=args.server,
        generated_at=generated_at,
        group_reports=group_reports,
        navigation=navigation,
        export_metadata=export_metadata,
    )
    save_text(html_report_path, html_report)
    print(f'  Saved: {html_report_path}')
    print()

    print('Export complete.')
    print()
    print(f'Output folder: {output_dir}')
    print(f'HTML report: {html_report_path}')
    print()
    print('Summary:')
    print(f'  Policy groups : {len(group_reports)}')
    print(f'  Enforcement Agents : {len(agents)}')
    print(f'  Allowlists    : {len(all_export_refs["allowlist"])}')
    print(f'  Baselines     : {len(all_export_refs["baseline"])}')
    print(f'  Blocklists    : {len(all_export_refs["blocklist"])}')


if __name__ == '__main__':
    try:
        main()
    except requests.exceptions.RequestException as exc:
        print(f'ERROR: API request failed: {exc}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nCancelled by user.', file=sys.stderr)
        sys.exit(130)
