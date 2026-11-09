# Tests for vuln_matcher.py. Run them with:  pytest
import io
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import app.vuln_matcher as vm
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


# =====================================================================
# Live NVD lookup. Every test here uses FAKE NVD answers.
# =====================================================================
@pytest.fixture(autouse=True)
def no_real_network(monkeypatch, tmp_path):
    """No test may touch the real network, and none may write the real cache file."""

    def blocked(*args, **kwargs):
        raise AssertionError("A test tried to use the real network!")

    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(vm, "NVD_CACHE_PATH", tmp_path / "nvd_cache.json")
    monkeypatch.setattr(vm, "_last_request_at", 0.0)
    monkeypatch.delenv("NVD_API_KEY", raising=False)


def fake_cve(cve_id, score=None, key="cvssMetricV31", description="A flaw. More text.", status="Analyzed"):
    """One CVE, shaped like an NVD answer."""
    cve = {"id": cve_id, "vulnStatus": status, "descriptions": [{"lang": "en", "value": description}], "metrics": {}}
    if score is not None:
        cve["metrics"][key] = [{"type": "Primary", "cvssData": {"baseScore": score}}]
    return {"cve": cve}


def fake_response(*items):
    return {"vulnerabilities": list(items)}


def ids(found):
    return [item["cve"] for item in found]


# ---------- the address and the names ----------
def test_the_only_address_is_the_nvd_api():
    assert vm.NVD_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"


def test_cpe_name_for_known_software():
    assert vm.cpe_name("Apache", "2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert vm.cpe_name("  MYSQL ", "5.7.30") == "cpe:2.3:a:oracle:mysql:5.7.30:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "software, version",
    [("Windows 10", "21H2"), ("Apache", ""), ("Apache", "latest"), ("Apache", "2.4.49:*"), ("", "1.0"), (None, None)],
)
def test_cpe_name_is_none_when_we_cannot_name_it(software, version):
    assert vm.cpe_name(software, version) is None


# ---------- reading an NVD answer ----------
def test_best_cvss_prefers_newer_scoring():
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
    }
    assert vm._best_cvss(metrics) == 7.5
    assert vm._best_cvss({"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}) == 5.0
    assert vm._best_cvss({"cvssMetricV30": [{"cvssData": {"baseScore": 6.1}}]}) == 6.1


def test_best_cvss_prefers_the_primary_score():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8}},
        ]
    }
    assert vm._best_cvss(metrics) == 9.8


def test_best_cvss_is_none_without_a_score():
    assert vm._best_cvss({}) is None


def test_short_description_keeps_the_first_sentence():
    descriptions = [{"lang": "en", "value": "A flaw lets attackers in.\nAnother sentence."}]
    assert vm._short_description(descriptions) == "A flaw lets attackers in."


def test_short_description_cuts_very_long_text():
    text = vm._short_description([{"lang": "en", "value": "word " * 100}])
    assert len(text) <= vm.MAX_DESCRIPTION_LENGTH and text.endswith("...")


def test_short_description_uses_english_and_has_a_fallback():
    spanish_first = [{"lang": "es", "value": "Hola. Adios."}, {"lang": "en", "value": "Hello there."}]
    assert vm._short_description(spanish_first) == "Hello there."
    assert vm._short_description([]) == "No description available."


def test_parse_skips_unscored_and_rejected_cves_and_sorts_worst_first():
    data = fake_response(
        fake_cve("CVE-2020-0001", 7.5),
        fake_cve("CVE-2020-0002"),  # no score yet
        fake_cve("CVE-2020-0003", 8.0, status="Rejected"),
        fake_cve("CVE-2020-0004", 9.8),
    )
    found = vm.parse_nvd_response(data)
    assert ids(found) == ["CVE-2020-0004", "CVE-2020-0001"]
    assert set(found[0]) == {"cve", "cvss", "description"}
    assert type(found[0]["cvss"]) is float


# ---------- lookup_nvd and the cache ----------
def test_lookup_asks_nvd_once_then_uses_the_cache(monkeypatch):
    urls = []

    def fake_request(url):
        urls.append(url)
        return fake_response(fake_cve("CVE-2021-41773", 7.5), fake_cve("CVE-2021-42013", 9.8))

    monkeypatch.setattr(vm, "_request_nvd", fake_request)
    first = vm.lookup_nvd("Apache", "2.4.49")
    assert ids(first) == ["CVE-2021-42013", "CVE-2021-41773"]

    url = urls[0]
    assert url.startswith(vm.NVD_URL + "?")
    assert "cpeName=cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" in url
    assert "&isVulnerable&" in url and "resultsPerPage=" in url

    assert vm.lookup_nvd("Apache", "2.4.49") == first
    assert len(urls) == 1  # the second answer came from the cache
    assert vm.NVD_CACHE_PATH.exists()


def test_an_empty_answer_is_cached_too(monkeypatch):
    calls = []
    monkeypatch.setattr(vm, "_request_nvd", lambda url: calls.append(url) or fake_response())
    assert vm.lookup_nvd("Samba", "4.18.0") == []
    assert vm.lookup_nvd("Samba", "4.18.0") == []
    assert len(calls) == 1


def test_an_old_cache_entry_is_asked_again(monkeypatch):
    cpe = vm.cpe_name("Apache", "2.4.49")
    old = (datetime.now(timezone.utc) - timedelta(days=vm.CACHE_DAYS + 1)).isoformat()
    vm.NVD_CACHE_PATH.write_text(json.dumps({cpe: {"fetched_at": old, "vulnerabilities": []}}))
    monkeypatch.setattr(vm, "_request_nvd", lambda url: fake_response(fake_cve("CVE-2021-41773", 7.5)))
    assert ids(vm.lookup_nvd("Apache", "2.4.49")) == ["CVE-2021-41773"]


def test_a_broken_cache_file_is_ignored(monkeypatch):
    vm.NVD_CACHE_PATH.write_text("{ not json")
    monkeypatch.setattr(vm, "_request_nvd", lambda url: fake_response(fake_cve("CVE-2021-41773", 7.5)))
    assert ids(vm.lookup_nvd("Apache", "2.4.49")) == ["CVE-2021-41773"]


def test_software_we_cannot_name_makes_no_request(monkeypatch):
    def forbidden(url):
        raise AssertionError("NVD should not be asked")

    monkeypatch.setattr(vm, "_request_nvd", forbidden)
    assert vm.lookup_nvd("Windows 10", "21H2") == []


def test_only_the_ten_worst_cves_are_kept(monkeypatch):
    items = [fake_cve(f"CVE-2020-{1000 + i}", 1 + i * 0.5) for i in range(15)]
    monkeypatch.setattr(vm, "_request_nvd", lambda url: fake_response(*items))
    found = vm.lookup_nvd("MySQL", "5.7.30")
    assert len(found) == vm.MAX_LIVE_CVES_PER_MACHINE
    assert found[0]["cvss"] == 8.0
    assert [f["cvss"] for f in found] == sorted((f["cvss"] for f in found), reverse=True)


# ---------- talking to NVD: waiting, retrying, errors ----------
def test_wait_for_turn_sleeps_until_the_gap_has_passed(monkeypatch):
    sleeps = []
    monkeypatch.setattr(vm.time, "sleep", sleeps.append)
    monkeypatch.setattr(vm, "_last_request_at", time.monotonic())
    vm._wait_for_turn(6.1)
    assert len(sleeps) == 1 and 0 < sleeps[0] <= 6.1


def test_wait_for_turn_does_not_sleep_when_enough_time_has_passed(monkeypatch):
    sleeps = []
    monkeypatch.setattr(vm.time, "sleep", sleeps.append)
    monkeypatch.setattr(vm, "_last_request_at", time.monotonic() - 100)
    vm._wait_for_turn(6.1)
    assert sleeps == []


def test_request_tries_again_when_nvd_is_busy(monkeypatch):
    sleeps, attempts = [], []
    monkeypatch.setattr(vm.time, "sleep", sleeps.append)

    def flaky(url, api_key):
        attempts.append(url)
        if len(attempts) < 3:
            raise vm._TryAgain("HTTP 403")
        return {"ok": True}

    monkeypatch.setattr(vm, "_download_once", flaky)
    assert vm._request_nvd(vm.NVD_URL + "?x=1") == {"ok": True}
    assert len(attempts) == 3
    assert sleeps.count(vm.RETRY_WAIT_SECONDS) == 2


def test_request_gives_up_with_a_clear_message(monkeypatch):
    attempts = []
    monkeypatch.setattr(vm.time, "sleep", lambda seconds: None)

    def always_busy(url, api_key):
        attempts.append(url)
        raise vm._TryAgain("HTTP 403")

    monkeypatch.setattr(vm, "_download_once", always_busy)
    with pytest.raises(vm.NvdError, match="try again"):
        vm._request_nvd(vm.NVD_URL + "?x=1")
    assert len(attempts) == vm.MAX_RETRIES + 1


def test_the_api_key_is_sent_but_never_shown_in_errors(monkeypatch):
    keys = []
    monkeypatch.setenv("NVD_API_KEY", "secret-key-123")
    monkeypatch.setattr(vm.time, "sleep", lambda seconds: None)

    def busy(url, api_key):
        keys.append(api_key)
        raise vm._TryAgain("HTTP 403")

    monkeypatch.setattr(vm, "_download_once", busy)
    with pytest.raises(vm.NvdError) as problem:
        vm._request_nvd(vm.NVD_URL + "?x=1")
    assert set(keys) == {"secret-key-123"}
    assert "secret-key-123" not in str(problem.value)


def test_download_sends_the_api_key_and_returns_json(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["request"], seen["timeout"] = request, timeout
        return io.BytesIO(b'{"vulnerabilities": []}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert vm._download_once(vm.NVD_URL + "?cpeName=x", "abc") == {"vulnerabilities": []}
    assert seen["request"].get_header("Apikey") == "abc"
    assert seen["timeout"] == vm.REQUEST_TIMEOUT


@pytest.mark.parametrize("address", ["https://evil.example/x?y=1", "http://services.nvd.nist.gov/rest/json/cves/2.0?x=1"])
def test_download_refuses_any_other_address(address):
    with pytest.raises(vm.NvdError, match="Refusing"):
        vm._download_once(address, "")  # the blocked urlopen would fail the test if it were called


def raising(error):
    def fake_urlopen(request, timeout):
        raise error

    return fake_urlopen


@pytest.mark.parametrize("code", [403, 429, 503])
def test_busy_codes_mean_try_again(monkeypatch, code):
    error = urllib.error.HTTPError("u", code, "busy", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", raising(error))
    with pytest.raises(vm._TryAgain):
        vm._download_once(vm.NVD_URL + "?x=1", "")


def test_a_404_means_nothing_found(monkeypatch):
    error = urllib.error.HTTPError("u", 404, "not found", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", raising(error))
    assert vm._download_once(vm.NVD_URL + "?x=1", "") == {"vulnerabilities": []}


def test_other_http_errors_are_reported(monkeypatch):
    error = urllib.error.HTTPError("u", 500, "oops", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", raising(error))
    with pytest.raises(vm.NvdError, match="error 500"):
        vm._download_once(vm.NVD_URL + "?x=1", "")


def test_no_internet_is_reported_clearly(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", raising(urllib.error.URLError("Name or service not known")))
    with pytest.raises(vm.NvdError, match="internet connection"):
        vm._download_once(vm.NVD_URL + "?x=1", "")


@pytest.mark.parametrize("error", [urllib.error.URLError(TimeoutError()), TimeoutError()])
def test_timeouts_mean_try_again(monkeypatch, error):
    monkeypatch.setattr(urllib.request, "urlopen", raising(error))
    with pytest.raises(vm._TryAgain):
        vm._download_once(vm.NVD_URL + "?x=1", "")


def test_a_reply_that_is_not_json_is_reported(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout: io.BytesIO(b"<html>oops</html>"))
    with pytest.raises(vm.NvdError, match="not valid JSON"):
        vm._download_once(vm.NVD_URL + "?x=1", "")


# ---------- putting local and live together ----------
def test_merge_keeps_the_local_entry_and_sorts_worst_first():
    local = [{"cve": "CVE-1", "cvss": 7.5, "description": "local"}]
    live = [
        {"cve": "CVE-1", "cvss": 9.8, "description": "live"},
        {"cve": "CVE-2", "cvss": 8.0, "description": "extra"},
    ]
    merged = vm._merge(local, live)
    assert [(m["cve"], m["description"]) for m in merged] == [("CVE-2", "extra"), ("CVE-1", "local")]


def test_attach_with_live_adds_the_nvd_cves(monkeypatch):
    extra = [{"cve": "CVE-2021-42013", "cvss": 9.8, "description": "Extra."}]
    monkeypatch.setattr(vm, "lookup_nvd", lambda software, version: extra if software == "Apache" else [])
    graph = attach_vulnerabilities(sample_graph(), live=True)
    assert ids(graph.nodes[1]["vulnerabilities"]) == ["CVE-2021-42013", "CVE-2021-41773"]
    assert graph.nodes[5]["vulnerabilities"] == []


def test_attach_without_live_never_asks_nvd(monkeypatch):
    def forbidden(software, version):
        raise AssertionError("NVD should not be asked")

    monkeypatch.setattr(vm, "lookup_nvd", forbidden)
    graph = attach_vulnerabilities(sample_graph())
    assert ids(graph.nodes[1]["vulnerabilities"]) == ["CVE-2021-41773"]


def test_attach_passes_on_an_nvd_error(monkeypatch):
    def broken(software, version):
        raise vm.NvdError("Cannot reach NVD.")

    monkeypatch.setattr(vm, "lookup_nvd", broken)
    with pytest.raises(vm.NvdError, match="Cannot reach NVD"):
        attach_vulnerabilities(sample_graph(), live=True)
