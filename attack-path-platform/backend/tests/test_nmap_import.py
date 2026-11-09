# Tests for nmap_import.py. Run them with:  pytest
import io
from pathlib import Path

import pytest

from app.attacker import find_attack_paths
from app.graph_builder import build_graph
from app.ingest import load_network
from app.nmap_import import MAX_MACHINES, NmapImportError, import_nmap
from app.vuln_matcher import attach_vulnerabilities

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "nmap_scan.xml"


# ---------- tiny scans, built from text ----------
def port(number, service="http", product="", version="", state="open"):
    attributes = f' name="{service}"'
    attributes += f' product="{product}"' if product else ""
    attributes += f' version="{version}"' if version else ""
    return f'<port protocol="tcp" portid="{number}"><state state="{state}"/><service{attributes}/></port>'


def host(name, *ports, status="up"):
    hostnames = f'<hostnames><hostname name="{name}" type="PTR"/></hostnames>' if name else "<hostnames/>"
    return (
        f'<host><status state="{status}"/><address addr="10.9.8.7" addrtype="ipv4"/>'
        f'<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>{hostnames}<ports>{"".join(ports)}</ports></host>'
    )


def scan(*hosts):
    return '<?xml version="1.0"?><nmaprun scanner="nmap">' + "".join(hosts) + "</nmaprun>"


def run(xml):
    return import_nmap(io.BytesIO(xml.encode()))


def rows(csv_text):
    """CSV text -> list of lists (header first)."""
    return [line.split(",") for line in csv_text.strip().split("\n")]


def machines(draft):
    """The machines as dicts, keyed by column name."""
    table = rows(draft["nodes_csv"])
    return [dict(zip(table[0], row)) for row in table[1:]]


# ---------- the example scan ----------
def test_example_scan_machines():
    draft = import_nmap(SAMPLE)
    found = machines(draft)
    assert [m["name"] for m in found] == ["web01", "app01", "files01", "db01", "printer01"]
    assert [m["type"] for m in found] == ["web_server", "app_server", "file_server", "database", "printer"]
    assert [(m["software"], m["version"]) for m in found] == [
        ("Apache", "2.4.49"), ("Apache", "2.4.48"), ("Samba", ""), ("MySQL", "5.7.30"), ("CUPS", "2.3"),
    ]
    assert [m["is_entry_point"] for m in found] == ["yes", "no", "no", "no", "no"]
    assert [m["is_sensitive"] for m in found] == ["no", "no", "no", "yes", "no"]


def test_example_scan_connections():
    table = rows(import_nmap(SAMPLE)["edges_csv"])
    assert table[0] == ["source", "target", "connection", "port"]
    assert table[1:] == [
        ["1", "2", "network_access", "8080"], ["1", "3", "network_access", "139"],
        ["1", "5", "network_access", "631"], ["2", "4", "db_access", "3306"],
        ["3", "4", "db_access", "3306"], ["5", "4", "db_access", "3306"],
    ]


def test_example_scan_guesses():
    text = "\n".join(import_nmap(SAMPLE)["guesses"])
    assert "Found 5 machines" in text
    assert "Skipped 1 host" in text
    assert "Entry points (guess: port 80 or 443 is open): web01." in text
    assert "Sensitive machines (guess: a database port is open): db01." in text
    assert "web01 also runs OpenSSH 7.4" in text
    assert "files01: the version of Samba is unclear ('3.X - 4.X')" in text
    assert "Shared logins cannot be seen" in text


def test_no_ip_or_mac_address_is_copied():
    draft = import_nmap(SAMPLE)
    everything = draft["nodes_csv"] + draft["edges_csv"] + "\n".join(draft["guesses"]).replace(
        "IP addresses and MAC addresses were not copied", ""
    )
    assert "192.168" not in everything and "08:00:27" not in everything


def test_the_draft_files_pass_the_normal_checks_and_give_a_path():
    draft = import_nmap(SAMPLE)
    nodes, edges = load_network(io.StringIO(draft["nodes_csv"]), io.StringIO(draft["edges_csv"]))
    graph = attach_vulnerabilities(build_graph(nodes, edges))
    assert [p["nodes"] for p in find_attack_paths(graph)] == [[1, 2, 4]]  # web01 -> app01 -> db01


def test_a_path_string_a_path_object_and_an_open_file_all_work():
    first = import_nmap(str(SAMPLE))
    assert import_nmap(SAMPLE) == first
    with open(SAMPLE, "rb") as file:
        assert import_nmap(file) == first


def test_result_has_the_three_parts():
    assert set(import_nmap(SAMPLE)) == {"nodes_csv", "edges_csv", "guesses"}


# ---------- machine types, entry points and sensitive machines ----------
def test_a_web_server_with_a_database_is_both_entry_and_sensitive():
    found = machines(run(scan(host("lamp", port(80, product="Apache httpd", version="2.4.49"), port(3306, "mysql", "MySQL", "5.7.30")))))
    assert found[0]["type"] == "database"  # the database is the most important program
    assert (found[0]["is_entry_point"], found[0]["is_sensitive"]) == ("yes", "yes")


def test_ssh_only_machine_is_a_server_with_openssh():
    found = machines(run(scan(host("box", port(22, "ssh", "OpenSSH", "7.4")), host("web", port(80)))))
    assert (found[0]["type"], found[0]["software"], found[0]["version"]) == ("server", "OpenSSH", "7.4")


def test_remote_desktop_machine_is_a_workstation():
    found = machines(run(scan(host("pc", port(3389, "ms-wbt-server")), host("web", port(80)))))
    assert found[0]["type"] == "workstation"


def test_main_program_order_is_database_then_web_then_the_rest():
    ports = [port(22, "ssh", "OpenSSH", "7.4"), port(8080, "http", "Apache httpd", "2.4.48"), port(5432, "postgresql", "PostgreSQL DB", "13.2")]
    found = machines(run(scan(host("m", *ports), host("web", port(80)))))
    assert (found[0]["type"], found[0]["software"], found[0]["version"]) == ("database", "PostgreSQL", "13.2")


def test_only_open_ports_count():
    xml = scan(host("web", port(80)), host("hidden", port(80, state="filtered"), port(22, state="closed")))
    draft = run(xml)
    assert [m["name"] for m in machines(draft)] == ["web"]
    assert "Skipped 1 host" in "\n".join(draft["guesses"])


# ---------- software and versions ----------
def test_product_names_are_changed_to_the_names_we_know():
    xml = scan(
        host("a", port(80, product="Apache httpd", version="2.4.49")),
        host("b", port(445, "netbios-ssn", "Samba smbd", "4.6.2")),
        host("c", port(5432, "postgresql", "PostgreSQL DB", "13.2")),
        host("d", port(9999, "other", "Foo Bar", "1.0")),
    )
    assert [m["software"] for m in machines(run(xml))] == ["Apache", "Samba", "PostgreSQL", "Foo Bar"]


def test_unclear_missing_and_unknown_versions_are_left_blank_with_a_note():
    xml = scan(
        host("unclear", port(445, "netbios-ssn", "Samba smbd", "3.X - 4.X")),
        host("missing", port(80, product="Apache httpd")),
        host("noprogram", port(8080, "http")),
    )
    draft = run(xml)
    assert [m["version"] for m in machines(draft)] == ["", "", ""]
    text = "\n".join(draft["guesses"])
    assert "the version of Samba is unclear ('3.X - 4.X')" in text
    assert "Nmap did not report the version of Apache" in text
    assert "Nmap could not tell what program runs on port 8080" in text


def test_a_hint_to_use_sv_when_there_are_no_program_names():
    draft = run(scan(host("a", port(80, "http")), host("b", port(3306, "mysql"))))
    assert "Run Nmap again with -sV" in "\n".join(draft["guesses"])


# ---------- names ----------
def test_machines_without_a_name_get_a_number_not_an_ip_address():
    found = machines(run(scan(host("", port(80)), host("", port(3306, "mysql")))))
    assert [m["name"] for m in found] == ["Host 1", "Host 2"]


def test_equal_names_are_made_different():
    found = machines(run(scan(host("web", port(80)), host("web", port(3306, "mysql")), host("WEB", port(22, "ssh")))))
    assert [m["name"] for m in found] == ["web", "web 2", "WEB 3"]


def test_names_and_software_are_safe_for_csv_and_excel():
    xml = scan(host("a,b", port(80)), host("=cmd|' /C calc'!A0", port(3306, "mysql", "-2+3", "1.0")))
    draft = run(xml)
    for m in machines(draft):
        assert not m["name"].startswith(("=", "+", "-", "@"))
        assert not m["software"].startswith(("=", "+", "-", "@"))
        assert "," not in m["name"]
    # the draft still passes the normal checks
    load_network(io.StringIO(draft["nodes_csv"]), io.StringIO(draft["edges_csv"]))


# ---------- connections ----------
def test_entry_points_connect_straight_to_sensitive_machines_when_nothing_is_in_between():
    draft = run(scan(host("web", port(80)), host("db", port(3306, "mysql"))))
    assert rows(draft["edges_csv"])[1:] == [["1", "2", "db_access", "3306"]]


def test_a_machine_that_is_entry_and_sensitive_does_not_connect_to_itself():
    draft = run(scan(host("lamp", port(80), port(3306, "mysql"))))
    assert rows(draft["edges_csv"]) == [["source", "target", "connection", "port"]]
    assert "No connections could be drawn" in "\n".join(draft["guesses"])


def test_no_entry_point_and_no_sensitive_machine_are_explained():
    text = "\n".join(run(scan(host("a", port(22, "ssh")), host("b", port(445, "microsoft-ds"))))["guesses"])
    assert "No entry point was found" in text
    assert "No sensitive machine was found" in text


def test_one_machine_uses_the_singular():
    assert "Found 1 machine that" in run(scan(host("a", port(80))))["guesses"][0]


# ---------- problems with the file ----------
@pytest.mark.parametrize(
    "content, message",
    [
        (b"hello", "not valid XML"),
        (b"", "not valid XML"),
        (b"<html><body/></html>", "does not look like an Nmap XML file"),
        (scan(host("down", port(80), status="down")).encode(), "no machine that is up"),
        (scan(host("closed", port(80, state="closed"))).encode(), "no machine that is up"),
        (b'<?xml version="1.0"?><nmaprun></nmaprun>', "no machine that is up"),
    ],
)
def test_bad_files_give_a_clear_message(content, message):
    with pytest.raises(NmapImportError, match=message):
        import_nmap(io.BytesIO(content))


def test_dangerous_xml_is_refused():
    evil = b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "boom">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(NmapImportError, match="not allowed for safety"):
        import_nmap(io.BytesIO(evil))


def test_a_missing_file_gives_a_clear_message(tmp_path):
    with pytest.raises(NmapImportError, match="could not be read"):
        import_nmap(tmp_path / "nothing.xml")


def test_too_many_machines_are_refused():
    xml = scan(*[host(f"h{i}", port(80)) for i in range(MAX_MACHINES + 1)])
    with pytest.raises(NmapImportError, match="The limit is 100"):
        run(xml)


def test_exactly_the_limit_is_fine():
    xml = scan(*[host(f"h{i}", port(80)) for i in range(MAX_MACHINES)])
    assert len(machines(run(xml))) == MAX_MACHINES
