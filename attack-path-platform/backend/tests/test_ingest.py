# Tests for ingest.py. Run them with:  pytest
import io
from pathlib import Path

import pytest

from app.ingest import IngestError, load_edges, load_network, load_nodes

SAMPLE = Path(__file__).parent.parent / "data" / "sample"

GOOD_NODES = (
    "id,name,type,software,version,is_entry_point,is_sensitive\n"
    "1,Web,web_server,Apache,2.4.49,yes,no\n"
    "2,DB,database,MySQL,5.7,no,yes\n"
)


def text(content):
    """Make a fake file from a string, so tests need no real files."""
    return io.StringIO(content)


# ---------- the sample files ----------
def test_sample_files_load():
    nodes, edges = load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv")
    assert len(nodes) == 6
    assert len(edges) == 6
    assert set(nodes[nodes["is_entry_point"]]["id"]) == {1, 2}
    assert set(nodes[nodes["is_sensitive"]]["id"]) == {4, 6}


def test_types_are_converted():
    nodes, edges = load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv")
    assert nodes["id"].iloc[0] == 1  # a number, not "1"
    assert nodes["version"].iloc[1] == "2016"  # stays text
    assert edges["port"].iloc[0] == 445


# ---------- nodes.csv problems ----------
def test_missing_node_column():
    bad = "id,name,type,software,is_entry_point,is_sensitive\n1,Web,web_server,Apache,yes,no\n"
    with pytest.raises(IngestError, match="missing column.*version"):
        load_nodes(text(bad))


def test_empty_file():
    with pytest.raises(IngestError, match="empty"):
        load_nodes(text(""))


def test_header_only():
    header = "id,name,type,software,version,is_entry_point,is_sensitive\n"
    with pytest.raises(IngestError, match="no data rows"):
        load_nodes(text(header))


def test_bad_yes_no():
    bad = GOOD_NODES.replace("Apache,2.4.49,yes,no", "Apache,2.4.49,maybe,no")
    with pytest.raises(IngestError, match="line 2.*is_entry_point.*'yes' or 'no'"):
        load_nodes(text(bad))


def test_id_not_a_number():
    bad = GOOD_NODES.replace("1,Web", "abc,Web")
    with pytest.raises(IngestError, match="line 2.*id 'abc'"):
        load_nodes(text(bad))


def test_duplicate_id():
    bad = GOOD_NODES.replace("2,DB", "1,DB")
    with pytest.raises(IngestError, match="line 3.*id 1 is already used on line 2"):
        load_nodes(text(bad))


def test_blank_name():
    bad = GOOD_NODES.replace("1,Web", "1,")
    with pytest.raises(IngestError, match="name must not be blank"):
        load_nodes(text(bad))


def test_spaces_and_capitals_are_accepted():
    messy = (
        "id , name,type,software,version,is_entry_point,is_sensitive\n"
        " 1 , Web ,web_server,,, YES , No \n"
    )
    nodes = load_nodes(text(messy))
    assert nodes["name"].iloc[0] == "Web"
    assert nodes["software"].iloc[0] == ""  # blank software is allowed
    assert bool(nodes["is_entry_point"].iloc[0]) is True
    assert bool(nodes["is_sensitive"].iloc[0]) is False


def test_extra_columns_are_ignored():
    extra = GOOD_NODES.replace("is_sensitive\n", "is_sensitive,notes\n").replace("no\n", "no,hello\n")
    nodes = load_nodes(text(extra))
    assert "notes" not in nodes.columns


# ---------- edges.csv problems ----------
def edges_text(row):
    return "source,target,connection,port\n" + row + "\n"


def test_missing_edge_column():
    with pytest.raises(IngestError, match="missing column.*port"):
        load_edges(text("source,target,connection\n1,2,network_access\n"), {1, 2})


def test_edge_to_unknown_machine():
    with pytest.raises(IngestError, match="target 9 is not an id in nodes.csv"):
        load_edges(text(edges_text("1,9,network_access,445")), {1, 2})


def test_bad_connection_type():
    with pytest.raises(IngestError, match="connection 'wifi' is not allowed"):
        load_edges(text(edges_text("1,2,wifi,445")), {1, 2})


def test_bad_port():
    with pytest.raises(IngestError, match="port 70000 must be between"):
        load_edges(text(edges_text("1,2,network_access,70000")), {1, 2})


def test_port_not_a_number():
    with pytest.raises(IngestError, match="port 'http' must be a whole number"):
        load_edges(text(edges_text("1,2,network_access,http")), {1, 2})


def test_machine_connected_to_itself():
    with pytest.raises(IngestError, match="cannot connect to itself"):
        load_edges(text(edges_text("1,1,network_access,445")), {1, 2})


def test_good_edge():
    edges = load_edges(text(edges_text("1,2,db_access,3306")), {1, 2})
    assert list(edges["connection"]) == ["db_access"]
