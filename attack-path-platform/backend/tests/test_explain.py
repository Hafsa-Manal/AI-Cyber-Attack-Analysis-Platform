# Tests for explain.py. Run them with:  pytest
import io
import json
from pathlib import Path

from app.attacker import find_attack_paths
from app.explain import _join_names, explain_all, explain_risk, suggest_fix
from app.graph_builder import build_graph
from app.ingest import load_network
from app.risk import rank_risks
from app.vuln_matcher import attach_vulnerabilities

SAMPLE = Path(__file__).parent.parent / "data" / "sample"

NODE_HEADER = "id,name,type,software,version,is_entry_point,is_sensitive\n"
EDGE_HEADER = "source,target,connection,port\n"


def sample():
    """The sample network, with everything ready for explain.py."""
    graph = attach_vulnerabilities(build_graph(*load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv")))
    paths = find_attack_paths(graph)
    risks = rank_risks(graph, paths)
    return graph, paths, risks


def make_graph(nodes, edges):
    return build_graph(*load_network(io.StringIO(NODE_HEADER + nodes), io.StringIO(EDGE_HEADER + edges)))


def add_cve(graph, node_id, cvss, cve=None):
    graph.nodes[node_id]["vulnerabilities"].append(
        {"cve": cve or f"CVE-TEST-{node_id}", "cvss": cvss, "description": "Test flaw."}
    )


# ---------- the whole result ----------
def test_every_risk_gets_an_explanation_and_a_fix():
    graph, paths, risks = sample()
    explained, fixes = explain_all(graph, paths, risks)
    assert len(explained) == len(fixes) == 6
    assert [r["node"] for r in explained] == [f["node"] for f in fixes] == [r["node"] for r in risks]
    for risk, fix in zip(explained, fixes):
        assert len(risk["explanation"]) > 20
        assert len(fix["fix"]) > 20


def test_result_has_the_contract_2_fields_and_can_become_json():
    graph, paths, risks = sample()
    explained, fixes = explain_all(graph, paths, risks)
    assert list(explained[0]) == ["node", "score", "level", "explanation"]
    assert list(fixes[0]) == ["node", "fix"]
    json.dumps({"risks": explained, "fixes": fixes})


def test_the_risks_passed_in_are_not_changed():
    graph, paths, risks = sample()
    explain_all(graph, paths, risks)
    assert "explanation" not in risks[0]


def test_no_text_contains_python_leftovers():
    graph, paths, risks = sample()
    explained, fixes = explain_all(graph, paths, risks)
    for text in [r["explanation"] for r in explained] + [f["fix"] for f in fixes]:
        assert "None" not in text and "nan" not in text and "{" not in text


# ---------- explanations on the sample network ----------
def test_file_server_explanation():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 3)
    assert "File Server runs Samba 3.5.0" in text
    assert "critical-severity" in text and "CVE-2017-7494" in text and "CVSS 9.8" in text
    assert "Short description: Lets an attacker upload a file" in text
    assert "Every attack path (4 of 4) goes through it" in text
    assert "From here the attacker can reach Customer Database and Domain Controller." in text
    assert "T1210 Exploitation of Remote Services" in text


def test_admin_workstation_has_no_flaws_but_a_shared_login():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 5)
    assert "no known flaws" in text
    assert "log in to it from File Server with a shared login" in text
    assert "T1078 Valid Accounts" in text
    assert "2 of the 4 attack paths" in text


def test_domain_controller_is_sensitive():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 6)
    assert "sensitive machine" in text
    assert "CVE-2020-1472" in text
    assert "T1078 Valid Accounts" in text


def test_public_website_is_an_entry_point():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 1)
    assert "entry point" in text
    assert "T1190 Exploit Public-Facing Application" in text
    assert "T1210" not in text  # that technique is used against the machines behind it


def test_customer_database_explanation():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 4)
    assert "medium-severity" in text  # CVSS 4.9
    assert "sensitive machine" in text
    assert "T1210 Exploitation of Remote Services" in text


def test_employee_laptop_is_on_part_of_the_paths():
    graph, paths, _ = sample()
    text = explain_risk(graph, paths, 2)
    assert "entry point" in text
    assert "It is on 2 of the 4 attack paths." in text


# ---------- fixes on the sample network ----------
def test_file_server_fix():
    graph, paths, _ = sample()
    fix = suggest_fix(graph, paths, 3)
    assert "Update Samba 3.5.0 to the latest patched version to fix CVE-2017-7494." in fix
    assert "Block port 445 on File Server from Public Website and Employee Laptop" in fix


def test_admin_workstation_fix_is_about_logins():
    graph, paths, _ = sample()
    fix = suggest_fix(graph, paths, 5)
    assert "multi-factor login" in fix
    assert "Update" not in fix  # no flaws, so nothing to update


def test_public_website_fix_mentions_a_network_zone():
    graph, paths, _ = sample()
    fix = suggest_fix(graph, paths, 1)
    assert "Update Apache 2.4.49" in fix and "DMZ" in fix


def test_database_fix():
    graph, paths, _ = sample()
    fix = suggest_fix(graph, paths, 4)
    assert "Block port 3306 on Customer Database from File Server" in fix
    assert "logging" in fix


def test_a_fix_has_at_most_three_actions():
    graph, paths, _ = sample()
    fix = suggest_fix(graph, paths, 6)  # flaw + shared login + sensitive = 3 actions
    assert fix.count("Update") + fix.count("Stop sharing") + fix.count("Allow access") == 3


# ---------- special cases ----------
def test_one_flaw_and_several_flaws_read_differently():
    graph = make_graph("1,A,workstation,App,1.0,yes,no\n2,B,database,App,1.0,no,yes\n", "1,2,shared_login,22\n")
    add_cve(graph, 1, 7.0)
    add_cve(graph, 2, 5.0, "CVE-TEST-2A")
    add_cve(graph, 2, 9.0, "CVE-TEST-2B")
    paths = find_attack_paths(graph)
    assert "has a high-severity known flaw (CVE-TEST-1, CVSS 7.0)" in explain_risk(graph, paths, 1)
    many = explain_risk(graph, paths, 2)
    assert "has 2 known flaws. The most serious is CVE-TEST-2B (critical severity, CVSS 9.0)." in many


def test_single_path_wording():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,shared_login,22\n")
    assert "The only attack path goes through it." in explain_risk(graph, find_attack_paths(graph), 2)


def test_network_with_no_paths():
    graph = make_graph("1,A,workstation,App,1.0,yes,no\n2,B,database,,,no,yes\n", "1,2,network_access,445\n")
    add_cve(graph, 1, 8.0)  # machine 2 has no flaw, so there is no path
    paths = find_attack_paths(graph)
    assert paths == []
    assert "No attack path was found" in explain_risk(graph, paths, 1)
    assert "Update App 1.0" in suggest_fix(graph, paths, 1)


def test_machine_off_every_path():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n3,C,workstation,,,no,no\n",
        "1,2,shared_login,22\n3,1,network_access,22\n",
    )
    paths = find_attack_paths(graph)
    assert "No attack path goes through this machine." in explain_risk(graph, paths, 3)


def test_fallback_fix_when_nothing_else_applies():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n3,C,workstation,,,no,no\n",
        "1,2,shared_login,22\n3,1,network_access,22\n",
    )
    fix = suggest_fix(graph, find_attack_paths(graph), 3)
    assert fix == "Keep C up to date and limit who can connect to it."


def test_join_names():
    assert _join_names([]) == ""
    assert _join_names(["A"]) == "A"
    assert _join_names(["A", "B"]) == "A and B"
    assert _join_names(["A", "B", "C"]) == "A, B and C"
