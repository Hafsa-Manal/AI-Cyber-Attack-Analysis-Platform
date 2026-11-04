# Tests for vuln_matcher.py. Run them with:  pytest
import json
import re
from pathlib import Path

import pytest

from app.graph_builder import build_graph, graph_to_dict
from app.ingest import load_network
from app.vuln_matcher import (
    VulnDatabaseError,
    attach_vulnerabilities,
    find_vulnerabilities,
    load_vuln_db,
    version_in_range,
)

SAMPLE = Path(__file__).parent.parent / "data" / "sample"


def sample_graph():
    return build_graph(*load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv"))


def cve_ids(found):
    return [item["cve"] for item in found]


# ---------- version_in_range ----------
def test_version_inside_the_range():
    assert version_in_range("2.4.49", "2.4.0", "2.4.50")


def test_both_ends_are_included():
    assert version_in_range("2.4.49", "2.4.49", "2.4.49")
    assert version_in_range("5.7.30", "5.7.0", "5.7.30")


def test_version_below_the_range():
    assert not version_in_range("2.4.48", "2.4.49", "2.4.50")


def test_version_above_the_range():
    assert not version_in_range("2.4.50", "2.4.0", "2.4.49")


def test_numbers_are_compared_not_text():
    # as text "2.4.9" is bigger than "2.4.10", but as numbers it is smaller
    assert version_in_range("2.4.9", "2.4.0", "2.4.10")


def test_short_versions_are_padded():
    assert version_in_range("2.0", "2.0.0", "2.0.0")


def test_no_minimum_means_no_lower_limit():
    assert version_in_range("0.1", None, "7.7")
    assert not version_in_range("7.8", None, "7.7")


def test_versions_with_letters():
    assert version_in_range("21H2", "21", "21.9")


def test_unknown_version_never_matches():
    assert not version_in_range("", "1", "9")
    assert not version_in_range("latest", "1", "9")


# ---------- find_vulnerabilities ----------
@pytest.fixture
def db():
    return load_vuln_db()


def test_exact_version_match(db):
    assert cve_ids(find_vulnerabilities("Apache", "2.4.49", db)) == ["CVE-2021-41773"]


def test_other_version_gets_other_cve(db):
    assert cve_ids(find_vulnerabilities("Apache", "2.4.48", db)) == ["CVE-2021-40438"]


def test_fixed_version_has_no_cve(db):
    assert find_vulnerabilities("Apache", "2.4.58", db) == []


def test_software_name_ignores_capitals_and_spaces(db):
    assert cve_ids(find_vulnerabilities("  apache ", "2.4.49", db)) == ["CVE-2021-41773"]


def test_unknown_or_blank_software(db):
    assert find_vulnerabilities("NotARealProgram", "1.0", db) == []
    assert find_vulnerabilities("", "1.0", db) == []


def test_worst_cvss_comes_first():
    tiny_db = [
        {"cve": "CVE-1", "software": "App", "cvss": 4.0, "description": "low"},
        {"cve": "CVE-2", "software": "App", "cvss": 9.0, "description": "high"},
    ]
    assert cve_ids(find_vulnerabilities("App", "1.0", tiny_db)) == ["CVE-2", "CVE-1"]


def test_each_vulnerability_has_the_contract_1_fields(db):
    found = find_vulnerabilities("Samba", "3.5.0", db)
    assert set(found[0]) == {"cve", "cvss", "description"}


# ---------- attach_vulnerabilities on the sample network ----------
def test_sample_network_gets_the_expected_cves():
    graph = attach_vulnerabilities(sample_graph())
    expected = {
        1: ["CVE-2021-41773"],  # Apache 2.4.49
        2: ["CVE-2017-11882"],  # Microsoft Office 2016
        3: ["CVE-2017-7494"],  # Samba 3.5.0
        4: ["CVE-2020-14812"],  # MySQL 5.7.30
        5: [],  # Windows 10 21H2 has no match
        6: ["CVE-2020-1472"],  # Windows Server 2016
    }
    for node_id, cves in expected.items():
        assert cve_ids(graph.nodes[node_id]["vulnerabilities"]) == cves


def test_attach_returns_the_same_graph():
    graph = sample_graph()
    assert attach_vulnerabilities(graph) is graph


def test_graph_with_cves_can_become_json():
    graph = attach_vulnerabilities(sample_graph())
    text = json.dumps(graph_to_dict(graph))
    assert "CVE-2021-41773" in text


# ---------- the database file itself ----------
def test_real_database_is_valid(db):
    assert len(db) > 0
    for entry in db:
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", entry["cve"])
        assert 0 <= entry["cvss"] <= 10


def test_missing_database_file(tmp_path):
    with pytest.raises(VulnDatabaseError, match="not found"):
        load_vuln_db(tmp_path / "nothing.json")


def test_broken_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    with pytest.raises(VulnDatabaseError, match="not valid JSON"):
        load_vuln_db(bad)


def test_entry_missing_a_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"vulnerabilities": [{"cve": "CVE-2020-0001", "software": "App", "cvss": 5}]}))
    with pytest.raises(VulnDatabaseError, match="entry 1 is missing 'description'"):
        load_vuln_db(bad)


def test_cvss_out_of_range(tmp_path):
    bad = tmp_path / "bad.json"
    entry = {"cve": "CVE-2020-0001", "software": "App", "cvss": 11, "description": "x"}
    bad.write_text(json.dumps({"vulnerabilities": [entry]}))
    with pytest.raises(VulnDatabaseError, match="cvss must be a number from 0 to 10"):
        load_vuln_db(bad)
