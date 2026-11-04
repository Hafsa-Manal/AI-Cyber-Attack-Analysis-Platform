# Tests for graph_builder.py. Run them with:  pytest
import io
import json
from pathlib import Path

import networkx as nx
import pytest

from app.graph_builder import GraphBuildError, build_graph, graph_to_dict
from app.ingest import load_network

SAMPLE = Path(__file__).parent.parent / "data" / "sample"

NODES = (
    "id,name,type,software,version,is_entry_point,is_sensitive\n"
    "1,Web,web_server,Apache,2.4.49,yes,no\n"
    "2,DB,database,MySQL,5.7,no,yes\n"
)


def sample_graph():
    nodes, edges = load_network(SAMPLE / "nodes.csv", SAMPLE / "edges.csv")
    return build_graph(nodes, edges)


def small_graph(edge_rows):
    """Build a tiny graph from NODES and some edge lines (a string)."""
    edges_csv = "source,target,connection,port\n" + edge_rows
    return build_graph(*load_network(io.StringIO(NODES), io.StringIO(edges_csv)))


def test_sample_graph_size():
    graph = sample_graph()
    assert isinstance(graph, nx.DiGraph)
    assert graph.number_of_nodes() == 6
    assert graph.number_of_edges() == 6


def test_node_details_are_kept():
    graph = sample_graph()
    web = graph.nodes[1]
    assert web["name"] == "Public Website"
    assert web["software"] == "Apache"
    assert web["version"] == "2.4.49"
    assert web["is_entry_point"] is True
    assert web["is_sensitive"] is False
    assert graph.nodes[4]["is_sensitive"] is True


def test_nodes_start_with_no_vulnerabilities():
    graph = sample_graph()
    assert all(data["vulnerabilities"] == [] for _, data in graph.nodes(data=True))


def test_edges_have_a_direction():
    graph = sample_graph()
    assert graph.has_edge(1, 3)
    assert not graph.has_edge(3, 1)  # the other way does not exist


def test_edge_details_are_kept():
    graph = sample_graph()
    assert graph.edges[3, 5]["connection"] == "shared_login"
    assert graph.edges[3, 4]["port"] == 3306


def test_second_connection_between_same_machines_is_rejected():
    rows = "1,2,network_access,445\n1,2,shared_login,3389\n"
    with pytest.raises(GraphBuildError, match="line 3.*already a connection from 1 to 2"):
        small_graph(rows)


def test_graph_to_dict_has_the_contract_1_shape():
    result = graph_to_dict(sample_graph())
    assert set(result) == {"nodes", "edges"}
    assert set(result["nodes"][0]) == {
        "id", "name", "type", "software", "version",
        "is_entry_point", "is_sensitive", "vulnerabilities",
    }
    assert set(result["edges"][0]) == {"source", "target", "connection", "port"}
    assert len(result["nodes"]) == 6
    assert len(result["edges"]) == 6


def test_graph_to_dict_can_become_json():
    # json.dumps fails if any value is a numpy type instead of a plain Python one
    text = json.dumps(graph_to_dict(sample_graph()))
    assert '"Public Website"' in text


def test_ids_are_plain_numbers_and_booleans():
    result = graph_to_dict(sample_graph())
    assert type(result["nodes"][0]["id"]) is int
    assert type(result["nodes"][0]["is_entry_point"]) is bool
    assert type(result["edges"][0]["port"]) is int
