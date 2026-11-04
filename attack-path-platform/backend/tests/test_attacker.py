# Tests for attacker.py. Run them with:  pytest
import io
import json
from pathlib import Path

import pytest

from app.attacker import TechniqueFileError, find_attack_paths, load_techniques
from app.graph_builder import build_graph
from app.ingest import load_network
from app.vuln_matcher import attach_vulnerabilities

SAMPLE = Path(__file__).parent.parent / "data" / "sample"

NODE_HEADER = "id,name,type,software,version,is_entry_point,is_sensitive\n"
EDGE_HEADER = "source,target,connection,port\n"


def sample_paths():
    graph = build_graph(*load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv"))
    return find_attack_paths(attach_vulnerabilities(graph))


def make_graph(nodes, edges):
    """Build a tiny graph from CSV lines. Machines start with NO vulnerabilities."""
    return build_graph(*load_network(io.StringIO(NODE_HEADER + nodes), io.StringIO(EDGE_HEADER + edges)))


def add_cve(graph, node_id, cvss):
    graph.nodes[node_id]["vulnerabilities"].append(
        {"cve": f"CVE-TEST-{node_id}", "cvss": cvss, "description": "test"}
    )


def chain(length):
    """A line of machines 1 -> 2 -> ... -> length joined by shared logins."""
    nodes = "".join(
        f"{i},M{i},workstation,,,{'yes' if i == 1 else 'no'},{'yes' if i == length else 'no'}\n"
        for i in range(1, length + 1)
    )
    edges = "".join(f"{i},{i + 1},shared_login,22\n" for i in range(1, length))
    return make_graph(nodes, edges)


def node_lists(paths):
    return [p["nodes"] for p in paths]


# ---------- the sample network ----------
def test_sample_network_has_four_paths():
    assert node_lists(sample_paths()) == [[1, 3, 4], [1, 3, 5, 6], [2, 3, 4], [2, 3, 5, 6]]


def test_blocked_connection_is_never_used():
    # 2 -> 5 is plain network access and machine 5 has no flaw, so the attacker cannot use it
    for path in sample_paths():
        pairs = list(zip(path["nodes"], path["nodes"][1:]))
        assert (2, 5) not in pairs


def test_sample_step_labels_through_the_shared_logins():
    path = sample_paths()[1]  # 1 -> 3 -> 5 -> 6
    assert [(s["technique_id"], s["via"]) for s in path["steps"]] == [
        ("T1190", "CVE-2021-41773"),
        ("T1078", None),
        ("T1078", None),
    ]


def test_sample_step_labels_through_remote_services():
    path = sample_paths()[2]  # 2 -> 3 -> 4
    assert [(s["technique_id"], s["via"]) for s in path["steps"]] == [
        ("T1210", "CVE-2017-7494"),
        ("T1210", "CVE-2020-14812"),
    ]
    assert path["steps"][0]["technique_name"] == "Exploitation of Remote Services"
    assert (path["steps"][0]["from"], path["steps"][0]["to"]) == (2, 3)


def test_result_can_become_json():
    assert "T1210" in json.dumps(sample_paths())


# ---------- the movement rule ----------
def two_machines(connection, cvss):
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n",
        f"1,2,{connection},445\n",
    )
    if cvss is not None:
        add_cve(graph, 2, cvss)
    return graph


def test_cvss_exactly_4_is_enough():
    assert node_lists(find_attack_paths(two_machines("network_access", 4.0))) == [[1, 2]]


def test_cvss_below_4_is_not_enough():
    assert find_attack_paths(two_machines("network_access", 3.9)) == []


def test_no_vulnerability_means_no_move():
    assert find_attack_paths(two_machines("network_access", None)) == []


def test_shared_login_works_without_any_vulnerability():
    assert node_lists(find_attack_paths(two_machines("shared_login", None))) == [[1, 2]]


def test_only_the_next_machine_needs_the_flaw():
    # the flaw must be on the machine the attacker moves INTO, not the one they leave
    graph = two_machines("network_access", None)
    add_cve(graph, 1, 9.0)  # flaw on the start machine only
    assert find_attack_paths(graph) == []


def test_connections_only_work_in_one_direction():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n",
        "2,1,shared_login,22\n",  # points from B to A, not from A to B
    )
    assert find_attack_paths(graph) == []


# ---------- starting points and goals ----------
def test_no_entry_point_means_no_paths():
    graph = make_graph("1,A,workstation,,,no,no\n2,B,database,,,no,yes\n", "1,2,shared_login,22\n")
    assert find_attack_paths(graph) == []


def test_no_sensitive_machine_means_no_paths():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,no\n", "1,2,shared_login,22\n")
    assert find_attack_paths(graph) == []


def test_machine_that_is_entry_and_sensitive_gives_no_path_to_itself():
    # ingest needs at least one connection, so machine 2 is just a neighbour
    graph = make_graph("1,A,database,,,yes,yes\n2,B,workstation,,,no,no\n", "1,2,shared_login,22\n")
    assert find_attack_paths(graph) == []


# ---------- path length and repeats ----------
def test_path_of_8_steps_is_found():
    assert len(find_attack_paths(chain(9))) == 1  # 9 machines = 8 steps


def test_path_of_9_steps_is_too_long():
    assert find_attack_paths(chain(10)) == []


def test_max_length_can_be_changed():
    assert len(find_attack_paths(chain(10), max_length=9)) == 1


def test_a_machine_is_never_visited_twice():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,workstation,,,no,no\n3,C,database,,,no,yes\n",
        "1,2,shared_login,22\n2,3,shared_login,22\n3,2,shared_login,22\n",  # 2 and 3 form a loop
    )
    paths = find_attack_paths(graph)
    assert node_lists(paths) == [[1, 2, 3]]
    for path in paths:
        assert len(set(path["nodes"])) == len(path["nodes"])


# ---------- which technique a step gets ----------
def web_to_database(web_type="web_server", web_is_entry="yes", connection="network_access", web_cvss=7.5):
    graph = make_graph(
        f"1,Web,{web_type},,,{web_is_entry},no\n2,DB,database,,,no,yes\n",
        f"1,2,{connection},445\n",
    )
    add_cve(graph, 2, 9.0)
    if web_cvss is not None:
        add_cve(graph, 1, web_cvss)
    return graph


def first_step(graph):
    return find_attack_paths(graph)[0]["steps"][0]


def test_vulnerable_public_web_server_gets_T1190():
    step = first_step(web_to_database())
    assert step["technique_id"] == "T1190"
    assert step["via"] == "CVE-TEST-1"  # the web server's own flaw
    assert step["technique_name"] == "Exploit Public-Facing Application"


def test_shared_login_beats_the_web_server_rule():
    step = first_step(web_to_database(connection="shared_login"))
    assert (step["technique_id"], step["via"]) == ("T1078", None)


def test_web_server_without_a_flaw_gets_T1210():
    step = first_step(web_to_database(web_cvss=None))
    assert (step["technique_id"], step["via"]) == ("T1210", "CVE-TEST-2")


def test_other_machine_types_get_T1210():
    step = first_step(web_to_database(web_type="workstation"))
    assert (step["technique_id"], step["via"]) == ("T1210", "CVE-TEST-2")


def test_web_server_that_is_not_public_gets_T1210():
    graph = make_graph(
        "1,Laptop,workstation,,,yes,no\n2,Web,web_server,,,no,no\n3,DB,database,,,no,yes\n",
        "1,2,network_access,445\n2,3,network_access,445\n",
    )
    for node_id in (2, 3):
        add_cve(graph, node_id, 8.0)
    second_step = find_attack_paths(graph)[0]["steps"][1]  # leaves the web server
    assert second_step["technique_id"] == "T1210"


def test_the_worst_cve_is_named():
    graph = two_machines("network_access", 5.0)
    add_cve(graph, 2, 9.5)
    assert first_step(graph)["via"] == "CVE-TEST-2"
    assert graph.nodes[2]["vulnerabilities"][1]["cvss"] == 9.5


# ---------- the technique file ----------
def test_technique_file_has_the_three_techniques():
    techniques = load_techniques()
    assert techniques["T1078"]["name"] == "Valid Accounts"
    assert techniques["T1190"]["name"] == "Exploit Public-Facing Application"
    assert techniques["T1210"]["name"] == "Exploitation of Remote Services"


def test_missing_technique_file(tmp_path):
    with pytest.raises(TechniqueFileError, match="not found"):
        load_techniques(tmp_path / "nothing.json")


def test_broken_technique_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ nope")
    with pytest.raises(TechniqueFileError, match="not valid JSON"):
        load_techniques(bad)


def test_technique_file_missing_one_technique(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"techniques": {"T1078": {"name": "Valid Accounts"}}}))
    with pytest.raises(TechniqueFileError, match="missing a name for T1190"):
        load_techniques(bad)
