"""graph_builder.py - turn the two clean tables from ingest.py into a graph.

A graph is just machines (called "nodes") joined by connections (called "edges").
We use a NetworkX DiGraph, a "directed graph": an edge from 1 to 3 means the
attacker can go from 1 to 3, but NOT from 3 back to 1.

SAFETY: this file only builds a picture in memory. It never touches a network.
"""
import networkx as nx


class GraphBuildError(ValueError):
    """A problem while building the graph. The message is safe to show to the user."""


def build_graph(nodes, edges):
    """Build the graph from the two tables returned by ingest.load_network()."""
    graph = nx.DiGraph()

    # 1. Add every machine. The machine id is the node's name inside the graph.
    for row in nodes.itertuples(index=False):
        graph.add_node(
            int(row.id),  # int(...) and bool(...) turn pandas values into plain Python values
            name=row.name,
            type=row.type,
            software=row.software,
            version=row.version,
            is_entry_point=bool(row.is_entry_point),
            is_sensitive=bool(row.is_sensitive),
            vulnerabilities=[],  # empty for now. vuln_matcher.py fills it in
        )

    # 2. Add every connection
    for position, row in enumerate(edges.itertuples(index=False)):
        line = position + 2  # line 1 of the file is the header
        source, target = int(row.source), int(row.target)

        # a connection must join two machines that exist
        for end, node_id in (("source", source), ("target", target)):
            if node_id not in graph:
                raise GraphBuildError(f"edges.csv line {line}: {end} {node_id} is not an id in nodes.csv.")

        # a graph keeps only one connection per pair, so a second one would be lost
        if graph.has_edge(source, target):
            raise GraphBuildError(
                f"edges.csv line {line}: there is already a connection from {source} to {target}. "
                "Use only one row for each pair of machines."
            )

        graph.add_edge(source, target, connection=row.connection, port=int(row.port))

    return graph


def graph_to_dict(graph):
    """Turn the graph into the "graph JSON" shape from Contract 1 (see docs/contracts.md)."""
    nodes = []
    for node_id, data in graph.nodes(data=True):
        nodes.append(
            {
                "id": node_id,
                "name": data["name"],
                "type": data["type"],
                "software": data["software"],
                "version": data["version"],
                "is_entry_point": data["is_entry_point"],
                "is_sensitive": data["is_sensitive"],
                "vulnerabilities": list(data["vulnerabilities"]),
            }
        )

    edges = []
    for source, target, data in graph.edges(data=True):
        edges.append(
            {
                "source": source,
                "target": target,
                "connection": data["connection"],
                "port": data["port"],
            }
        )

    return {"nodes": nodes, "edges": edges}
