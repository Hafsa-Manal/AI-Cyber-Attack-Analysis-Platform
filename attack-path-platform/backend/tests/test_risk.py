# Tests for risk.py. Run them with:  pytest
import io
import json
from pathlib import Path

import pytest

from app.attacker import find_attack_paths
from app.graph_builder import build_graph
from app.ingest import load_network
from app.risk import rank_risks, risk_level
from app.vuln_matcher import attach_vulnerabilities

SAMPLE = Path(__file__).parent.parent / "data" / "sample"

NODE_HEADER = "id,name,type,software,version,is_entry_point,is_sensitive\n"
EDGE_HEADER = "source,target,connection,port\n"


def make_graph(nodes, edges):
    """Build a tiny graph from CSV lines. Machines start with NO vulnerabilities."""
    return build_graph(*load_network(io.StringIO(NODE_HEADER + nodes), io.StringIO(EDGE_HEADER + edges)))


def add_cve(graph, node_id, cvss):
    graph.nodes[node_id]["vulnerabilities"].append(
        {"cve": f"CVE-TEST-{node_id}", "cvss": cvss, "description": "test"}
    )


def risks_for(graph):
    return rank_risks(graph, find_attack_paths(graph))


def score_of(risks, node_id):
    return next(r["score"] for r in risks if r["node"] == node_id)


def sample_risks():
    graph = attach_vulnerabilities(build_graph(*load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv")))
    return rank_risks(graph, find_attack_paths(graph))


# ---------- the sample network ----------
def test_sample_ranking_order():
    assert [r["node"] for r in sample_risks()] == [6, 3, 2, 1, 4, 5]


def test_sample_levels():
    assert [r["level"] for r in sample_risks()] == ["critical", "critical", "high", "high", "medium", "medium"]


def test_sample_scores():
    expected = {6: 9.0, 3: 8.9, 2: 6.5, 1: 6.2, 4: 5.4, 5: 4.5}
    scores = {r["node"]: r["score"] for r in sample_risks()}
    for node_id, score in expected.items():
        assert scores[node_id] == pytest.approx(score, abs=0.06)


def test_result_has_the_contract_2_fields_and_can_become_json():
    risks = sample_risks()
    assert set(risks[0]) == {"node", "score", "level"}  # explain.py adds "explanation"
    assert type(risks[0]["node"]) is int
    assert type(risks[0]["score"]) is float
    json.dumps(risks)


# ---------- the three parts of the score ----------
def test_best_possible_score_is_exactly_10():
    # worst flaw (10) = 7 points, on every path = 2 points, sensitive = 1 point
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,network_access,445\n")
    add_cve(graph, 2, 10.0)
    assert score_of(risks_for(graph), 2) == 10.0


def test_the_worst_cve_is_used():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,network_access,445\n")
    add_cve(graph, 2, 5.0)
    add_cve(graph, 2, 9.0)
    add_cve(graph, 2, 6.0)
    assert score_of(risks_for(graph), 2) == pytest.approx(0.7 * 9.0 + 2.0 + 1.0, abs=0.06)


def test_entry_machine_without_flaws_scores_only_for_its_paths():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,shared_login,22\n")
    risks = risks_for(graph)
    assert score_of(risks, 1) == 2.0  # on 1 of 1 paths
    assert [r for r in risks if r["node"] == 1][0]["level"] == "low"


def test_shared_login_counts_as_a_medium_flaw():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,shared_login,22\n")
    # B has no flaw, but is entered with a login: 0.7 x 5.0 + 2 + 1 = 6.5
    assert score_of(risks_for(graph), 2) == pytest.approx(6.5, abs=0.06)


def test_a_flaw_worse_than_5_beats_the_login_minimum():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,shared_login,22\n")
    add_cve(graph, 2, 10.0)
    assert score_of(risks_for(graph), 2) == 10.0


def test_login_minimum_only_counts_for_machines_on_a_path():
    # Machine 3 is entered by a shared login, but no path goes through it to a sensitive machine
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n3,C,workstation,,,no,no\n",
        "1,2,shared_login,22\n1,3,shared_login,22\n",
    )
    assert 3 not in [r["node"] for r in risks_for(graph)]


def test_machines_on_more_paths_score_higher():
    # 1 -> 2 -> 4 and 1 -> 3 -> 4 and 1 -> 3 -> 5. Machine 3 is on 2 paths, machine 2 on 1.
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,workstation,,,no,no\n3,C,workstation,,,no,no\n"
        "4,D,database,,,no,yes\n5,E,database,,,no,yes\n",
        "1,2,network_access,1\n1,3,network_access,1\n2,4,network_access,1\n"
        "3,4,network_access,1\n3,5,network_access,1\n",
    )
    for node_id in (2, 3, 4, 5):
        add_cve(graph, node_id, 6.0)  # same flaw everywhere
    risks = risks_for(graph)
    assert score_of(risks, 3) > score_of(risks, 2)


def test_without_paths_only_flaws_and_sensitivity_count():
    graph = make_graph("1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n", "1,2,network_access,445\n")
    add_cve(graph, 1, 8.0)
    add_cve(graph, 2, 3.9)  # too weak for the attacker, so there is no path
    risks = risks_for(graph)
    assert score_of(risks, 1) == pytest.approx(5.6, abs=0.06)
    assert score_of(risks, 2) == pytest.approx(0.7 * 3.9 + 1.0, abs=0.06)


def test_machine_with_nothing_to_report_is_left_out():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,database,,,no,yes\n3,C,workstation,,,no,no\n",
        "1,2,shared_login,22\n3,1,network_access,22\n",
    )
    assert 3 not in [r["node"] for r in risks_for(graph)]


def test_equal_scores_are_sorted_by_id():
    graph = make_graph(
        "1,A,workstation,,,yes,no\n2,B,workstation,,,yes,no\n3,C,database,,,no,yes\n",
        "1,3,shared_login,22\n2,3,shared_login,22\n",
    )
    risks = risks_for(graph)
    assert score_of(risks, 1) == score_of(risks, 2)
    assert [r["node"] for r in risks].index(1) < [r["node"] for r in risks].index(2)


def test_scores_stay_between_0_and_10():
    for risk in sample_risks():
        assert 0 < risk["score"] <= 10


# ---------- levels ----------
@pytest.mark.parametrize(
    "score, level",
    [(10, "critical"), (8.0, "critical"), (7.9, "high"), (6.0, "high"),
     (5.9, "medium"), (3.0, "medium"), (2.9, "low"), (0.1, "low")],
)
def test_risk_level(score, level):
    assert risk_level(score) == level
