import json
from argparse import Namespace

import pytest

import airlock_safe_mode_monitor as monitor


def test_required_list_distinguishes_verified_empty_from_unknown():
    assert monitor.required_list({"response": {"agents": []}}, "agents") == []
    with pytest.raises(RuntimeError, match="missing"):
        monitor.required_list({"response": {}}, "agents")
    with pytest.raises(RuntimeError, match="list of objects"):
        monitor.required_list({"response": {"agents": None}}, "agents")
    with pytest.raises(RuntimeError, match="list of objects"):
        monitor.required_list({"response": {"agents": ["bad"]}}, "agents")


def test_load_state_normalizes_ids_and_rejects_malformed_state(tmp_path):
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"safe_mode_agent_ids": [123, " 456 "]}))
    assert monitor.load_previous_safe_mode_agent_ids(state_file) == {"123", "456"}

    state_file.write_text(json.dumps({"safe_mode_agent_ids": "123"}))
    with pytest.raises(ValueError, match="must be a list"):
        monitor.load_previous_safe_mode_agent_ids(state_file)


@pytest.mark.parametrize("bad_id", [None, "", "   ", {}, []])
def test_load_state_rejects_invalid_ids(tmp_path, bad_id):
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"safe_mode_agent_ids": [bad_id]}))
    with pytest.raises(ValueError, match="invalid agent ID"):
        monitor.load_previous_safe_mode_agent_ids(state_file)


def test_canonicalize_agents_ignores_ineligible_and_is_order_independent():
    agents = [
        {"agentid": 2, "hostname": "z"},
        {"agentid": "2", "hostname": "a"},
        {"agentid": None, "hostname": "ignored"},
        {"hostname": "also-ignored"},
        {"agentid": " 1 ", "hostname": "one"},
    ]
    expected = [
        {"agentid": "1", "hostname": "one"},
        {"agentid": "2", "hostname": "a"},
    ]
    assert monitor.canonicalize_agents(agents) == expected
    assert monitor.canonicalize_agents(list(reversed(agents))) == expected


def test_duplicate_groups_are_resolved_independently_of_order():
    agents = [{"agentid": "1", "groupid": "10"}]
    groups = [{"groupid": "10", "name": "Zulu"}, {"groupid": 10, "name": "Alpha"}]
    assert monitor.add_group_names(agents, groups)[0]["groupname"] == "Alpha"
    assert monitor.add_group_names(agents, list(reversed(groups)))[0]["groupname"] == "Alpha"


def test_state_filename_uses_complete_server_identity():
    prod = monitor.default_state_file("airlock.prod.example")
    lab = monitor.default_state_file("airlock.lab.example")
    assert prod != lab
    assert "airlock_prod_example" in prod.name


def test_normalize_server_rejects_ambiguous_input_and_supports_ipv6():
    assert monitor.normalize_server("https://airlock.example:3129/") == (
        "https://airlock.example:3129",
        "airlock.example",
    )
    assert monitor.normalize_server("2001:db8::1") == (
        "https://[2001:db8::1]:3129",
        "2001:db8::1",
    )
    with pytest.raises(ValueError, match="only a hostname"):
        monitor.normalize_server("https://airlock.example/api?q=1")
    with pytest.raises(ValueError, match="port must be"):
        monitor.normalize_server("https://airlock.example:443")


def test_slack_message_chunking_respects_boundary_and_preserves_agents():
    agents = [
        {"agentid": str(index), "hostname": f"host-{index}", "groupname": "Group"}
        for index in range(5)
    ]
    one_length = len(monitor.build_slack_message(agents[:1], False))
    two_length = len(monitor.build_slack_message(agents[:2], False))

    at_limit = monitor.build_slack_messages(agents[:1], False, one_length)
    assert len(at_limit) == 1
    assert len(at_limit[0]) == one_length

    chunks = monitor.build_slack_messages(agents, False, two_length - 1)
    assert len(chunks) == len(agents)
    assert all(len(message) <= two_length - 1 for message in chunks)
    assert sum(message.count("host-") for message in chunks) == len(agents)

    with pytest.raises(ValueError, match="cannot fit"):
        monitor.build_slack_messages(agents[:1], False, one_length - 1)


def test_save_state_is_deterministic_and_excludes_missing_ids(tmp_path):
    state_file = tmp_path / "nested" / "state.json"
    monitor.save_current_state(
        state_file,
        "server.example",
        [
            {"agentid": "2", "hostname": "b", "groupname": "G"},
            {"hostname": "ignored", "groupname": "G"},
            {"agentid": "1", "hostname": "a", "groupname": "G"},
        ],
    )
    state = json.loads(state_file.read_text())
    assert state["safe_mode_agent_ids"] == ["1", "2"]
    assert len(state["safe_mode_agents"]) == 2
    assert not list(state_file.parent.glob("*.tmp"))


def test_failed_notification_does_not_advance_state(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"safe_mode_agent_ids": ["old"]}))
    monkeypatch.setattr(
        monitor,
        "get_safe_mode_agents",
        lambda **kwargs: [{"agentid": "new", "hostname": "host"}],
    )
    monkeypatch.setattr(monitor, "get_policy_groups", lambda **kwargs: [])

    def fail_delivery(*args, **kwargs):
        raise RuntimeError("delivery failed")

    monkeypatch.setattr(monitor, "send_slack_notification", fail_delivery)
    args = Namespace(api_key="key", slack_webhook="hook", notify_all=False)
    with pytest.raises(RuntimeError, match="delivery failed"):
        monitor.run_check(args, "https://server:3129", "server", True, state_file)

    assert json.loads(state_file.read_text())["safe_mode_agent_ids"] == ["old"]
