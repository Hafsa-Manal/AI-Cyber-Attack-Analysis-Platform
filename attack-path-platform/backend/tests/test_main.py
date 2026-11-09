# Tests for main.py (the API). Run them with:  pytest
from pathlib import Path

import urllib.request

import pytest
from fastapi.testclient import TestClient

import app.main as main
import app.vuln_matcher as vuln_matcher
from app.vuln_matcher import NvdError, VulnDatabaseError

SAMPLE = Path(__file__).parent.parent / "data" / "sample"
client = TestClient(main.app)

NODES_HEADER = "id,name,type,software,version,is_entry_point,is_sensitive\n"
EDGES_HEADER = "source,target,connection,port\n"


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """No test may touch the real network (not even NVD)."""

    def blocked(*args, **kwargs):
        raise AssertionError("A test tried to use the real network!")

    monkeypatch.setattr(urllib.request, "urlopen", blocked)


def upload(nodes_text, edges_text, live=False):
    """Send two CSV texts to /api/analyze, like the website does."""
    return client.post(
        "/api/analyze",
        params={"live": "true"} if live else {},
        files={
            "nodes": ("nodes.csv", nodes_text.encode(), "text/csv"),
            "edges": ("edges.csv", edges_text.encode(), "text/csv"),
        },
    )


def sample_texts():
    return (SAMPLE / "nodes.csv").read_text(), (SAMPLE / "edges.csv").read_text()


# ---------- GET /api/sample ----------
def test_sample_returns_contract_2():
    response = client.get("/api/sample")
    assert response.status_code == 200
    result = response.json()
    assert set(result) == {"graph", "paths", "risks", "fixes"}
    assert set(result["graph"]) == {"nodes", "edges"}
    assert len(result["graph"]["nodes"]) == 6
    assert len(result["graph"]["edges"]) == 6
    assert len(result["paths"]) == 4
    assert len(result["risks"]) == len(result["fixes"]) == 6


def test_sample_has_vulnerabilities_explanations_and_fixes():
    result = client.get("/api/sample").json()
    file_server = next(n for n in result["graph"]["nodes"] if n["id"] == 3)
    assert file_server["vulnerabilities"][0]["cve"] == "CVE-2017-7494"
    assert set(result["risks"][0]) == {"node", "score", "level", "explanation"}
    assert result["risks"][0]["explanation"]
    assert set(result["fixes"][0]) == {"node", "fix"}
    assert result["paths"][0]["steps"][0]["technique_id"] == "T1190"


# ---------- POST /api/analyze ----------
def test_uploading_the_sample_files_gives_the_sample_result():
    response = upload(*sample_texts())
    assert response.status_code == 200
    assert response.json() == client.get("/api/sample").json()


def test_network_with_no_entry_point_still_works():
    nodes = NODES_HEADER + "1,A,workstation,,,no,no\n2,B,database,,,no,yes\n"
    response = upload(nodes, EDGES_HEADER + "1,2,shared_login,22\n")
    assert response.status_code == 200
    assert response.json()["paths"] == []


def test_missing_column_gives_a_clear_400():
    nodes, edges = sample_texts()
    response = upload(nodes.replace("version", "ver"), edges)
    assert response.status_code == 400
    assert "missing column(s): version" in response.json()["detail"]


def test_empty_file_gives_a_clear_400():
    response = upload("", sample_texts()[1])
    assert response.status_code == 400
    assert "empty" in response.json()["detail"]


def test_connection_to_unknown_machine_gives_400():
    nodes, _ = sample_texts()
    response = upload(nodes, EDGES_HEADER + "1,99,network_access,445\n")
    assert response.status_code == 400
    assert "target 99 is not an id in nodes.csv" in response.json()["detail"]


def test_duplicate_connection_gives_400():
    nodes, _ = sample_texts()
    edges = EDGES_HEADER + "1,3,network_access,445\n1,3,shared_login,3389\n"
    response = upload(nodes, edges)
    assert response.status_code == 400
    assert "already a connection from 1 to 3" in response.json()["detail"]


def test_a_missing_file_gives_a_clear_400():
    response = client.post("/api/analyze", files={"nodes": ("nodes.csv", b"x", "text/csv")})
    assert response.status_code == 400
    assert response.json()["detail"] == "Please upload both nodes.csv and edges.csv."


def test_no_files_at_all_gives_400():
    assert client.post("/api/analyze").status_code == 400


def test_a_file_that_is_too_big_gives_413():
    big = "x" * (main.MAX_UPLOAD_BYTES + 1)
    response = upload(big, sample_texts()[1])
    assert response.status_code == 413
    assert "too big" in response.json()["detail"]


def test_problem_in_our_own_data_gives_500(monkeypatch):
    def broken(graph, live=False):
        raise VulnDatabaseError("vuln_db.json is not valid JSON")

    monkeypatch.setattr(main, "attach_vulnerabilities", broken)
    response = client.get("/api/sample")
    assert response.status_code == 500
    assert "Server data problem: vuln_db.json is not valid JSON" in response.json()["detail"]


# ---------- CORS (lets the website talk to the API) ----------
def test_the_website_origin_is_allowed():
    response = client.get("/api/sample", headers={"Origin": "http://localhost:5173"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_other_origins_are_not_allowed():
    response = client.get("/api/sample", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


# ---------- live NVD lookup (?live=true). NVD answers are FAKE here. ----------
EXTRA_APACHE_CVE = [{"cve": "CVE-2021-42013", "cvss": 9.8, "description": "Extra."}]


def fake_lookup(software, version):
    return EXTRA_APACHE_CVE if software == "Apache" else []


def website_cves(result):
    website = next(n for n in result["graph"]["nodes"] if n["id"] == 1)
    return [v["cve"] for v in website["vulnerabilities"]]


def test_live_lookup_is_off_by_default(monkeypatch):
    def forbidden(software, version):
        raise AssertionError("NVD should not be asked")

    monkeypatch.setattr(vuln_matcher, "lookup_nvd", forbidden)
    assert client.get("/api/sample").status_code == 200
    assert upload(*sample_texts()).status_code == 200


def test_sample_with_live_adds_nvd_cves(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "lookup_nvd", fake_lookup)
    response = client.get("/api/sample", params={"live": "true"})
    assert response.status_code == 200
    assert website_cves(response.json()) == ["CVE-2021-42013", "CVE-2021-41773"]


def test_upload_with_live_adds_nvd_cves(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "lookup_nvd", fake_lookup)
    response = upload(*sample_texts(), live=True)
    assert response.status_code == 200
    assert website_cves(response.json()) == ["CVE-2021-42013", "CVE-2021-41773"]


def test_live_false_means_off(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "lookup_nvd", fake_lookup)
    result = client.get("/api/sample", params={"live": "false"}).json()
    assert website_cves(result) == ["CVE-2021-41773"]


def test_nvd_problem_gives_502_with_a_clear_message(monkeypatch):
    def broken(software, version):
        raise NvdError("Cannot reach NVD. Check your internet connection.")

    monkeypatch.setattr(vuln_matcher, "lookup_nvd", broken)
    for response in (client.get("/api/sample", params={"live": "true"}), upload(*sample_texts(), live=True)):
        assert response.status_code == 502
        assert response.json()["detail"] == "Cannot reach NVD. Check your internet connection."


def test_a_bad_file_is_still_a_400_with_live_on(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "lookup_nvd", fake_lookup)
    nodes, edges = sample_texts()
    response = upload(nodes.replace("version", "ver"), edges, live=True)
    assert response.status_code == 400


# ---------- POST /api/import-nmap ----------
NMAP_SAMPLE = SAMPLE / "nmap_scan.xml"


def upload_scan(content):
    """Send an Nmap XML file (bytes) to /api/import-nmap, like the website does."""
    return client.post("/api/import-nmap", files={"scan": ("scan.xml", content, "text/xml")})


def test_nmap_scan_gives_a_draft():
    response = upload_scan(NMAP_SAMPLE.read_bytes())
    assert response.status_code == 200
    draft = response.json()
    assert set(draft) == {"nodes_csv", "edges_csv", "guesses"}
    assert draft["nodes_csv"].startswith("id,name,type,software,version,is_entry_point,is_sensitive\n")
    assert len(draft["nodes_csv"].strip().split("\n")) == 6  # header + 5 machines
    assert draft["edges_csv"].startswith("source,target,connection,port\n")
    assert all(isinstance(g, str) and g for g in draft["guesses"])


def test_the_draft_can_be_sent_straight_to_analyze():
    draft = upload_scan(NMAP_SAMPLE.read_bytes()).json()
    response = upload(draft["nodes_csv"], draft["edges_csv"])
    assert response.status_code == 200
    result = response.json()
    assert len(result["graph"]["nodes"]) == 5
    assert [p["nodes"] for p in result["paths"]] == [[1, 2, 4]]


def test_no_ip_addresses_leave_the_server():
    assert "192.168" not in upload_scan(NMAP_SAMPLE.read_bytes()).text


def test_nmap_endpoint_without_a_file_gives_a_clear_400():
    for response in (client.post("/api/import-nmap"), client.post("/api/import-nmap", files={"other": ("x.xml", b"x")})):
        assert response.status_code == 400
        assert "Please upload the Nmap scan file" in response.json()["detail"]


@pytest.mark.parametrize(
    "content, message",
    [
        (b"hello", "not valid XML"),
        (b"<html><body/></html>", "does not look like an Nmap XML file"),
        (b'<?xml version="1.0"?><nmaprun></nmaprun>', "no machine that is up"),
        (b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "boom">]><nmaprun>&a;</nmaprun>', "not allowed for safety"),
    ],
)
def test_bad_nmap_files_give_a_clear_400(content, message):
    response = upload_scan(content)
    assert response.status_code == 400
    assert message in response.json()["detail"]


def test_a_scan_with_too_many_machines_gives_400():
    hosts = "".join(
        f'<host><status state="up"/><ports><port portid="80"><state state="open"/><service name="http"/></port></ports></host>'
        for _ in range(101)
    )
    response = upload_scan(f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'.encode())
    assert response.status_code == 400
    assert "The limit is 100" in response.json()["detail"]


def test_a_scan_file_that_is_too_big_gives_413():
    response = upload_scan(b"x" * (main.MAX_UPLOAD_BYTES + 1))
    assert response.status_code == 413
    assert "scan.xml is too big" in response.json()["detail"]


def test_the_website_origin_is_allowed_for_the_scan_upload():
    response = client.post(
        "/api/import-nmap",
        headers={"Origin": "http://localhost:5173"},
        files={"scan": ("scan.xml", NMAP_SAMPLE.read_bytes(), "text/xml")},
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
