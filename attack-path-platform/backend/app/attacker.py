"""attacker.py - simulate an attacker who moves through the network graph.

The attacker starts at the entry points and tries to reach sensitive machines.
Rule-based: no learning, no guessing. It just follows the rules below.

THE RULES
- The attacker starts at every machine marked is_entry_point.
- The attacker can move along a connection from u to v if u is already reached AND
    (v has at least one vulnerability with cvss >= 4.0   OR   the connection is shared_login).
- The goal is any machine marked is_sensitive.
- We return ALL simple paths (no machine visited twice) up to 8 steps long.

SAFETY: this is a SIMULATION on a graph in memory. It never touches a real network.
"""
import json
from pathlib import Path

import networkx as nx

# The technique names live in backend/data/attack_techniques.json
TECHNIQUES_PATH = Path(__file__).parent.parent / "data" / "attack_techniques.json"

MIN_CVSS = 4.0  # a vulnerability must score at least this to be useful to the attacker
MAX_PATH_LENGTH = 8  # longest path, counted in steps (connections)

# The three techniques we use
VALID_ACCOUNTS = "T1078"  # shared login
PUBLIC_APP = "T1190"  # exploit a vulnerable public web server
REMOTE_SERVICES = "T1210"  # any other vulnerable step


class TechniqueFileError(ValueError):
    """A problem with attack_techniques.json. The message is safe to show to the user."""


def load_techniques(path=TECHNIQUES_PATH):
    """Read attack_techniques.json. Returns a dict like {"T1078": {"name": ..., "description": ...}}."""
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise TechniqueFileError(f"Technique file not found: {path}")
    except json.JSONDecodeError as error:
        raise TechniqueFileError(f"attack_techniques.json is not valid JSON: {error}")

    techniques = data.get("techniques") if isinstance(data, dict) else None
    if not isinstance(techniques, dict):
        raise TechniqueFileError("attack_techniques.json must have a 'techniques' object.")

    for technique_id in (VALID_ACCOUNTS, PUBLIC_APP, REMOTE_SERVICES):
        if "name" not in techniques.get(technique_id, {}):
            raise TechniqueFileError(f"attack_techniques.json is missing a name for {technique_id}.")
    return techniques


def worst_exploitable_cve(graph, node_id):
    """The most serious CVE of a machine that the attacker can use (cvss >= 4.0).
    Returns None if the machine has no such CVE."""
    usable = [v for v in graph.nodes[node_id]["vulnerabilities"] if v["cvss"] >= MIN_CVSS]
    if not usable:
        return None
    return max(usable, key=lambda v: v["cvss"])


def can_move(graph, source, target):
    """Can the attacker go from `source` to `target` along their connection?"""
    if graph.edges[source, target]["connection"] == "shared_login":
        return True  # a shared login works even if the machine has no flaws
    return worst_exploitable_cve(graph, target) is not None


def label_step(graph, source, target, techniques):
    """Say which MITRE ATT&CK technique one step uses, and what made it possible.
    Only call this for a step that can_move() allowed."""
    if graph.edges[source, target]["connection"] == "shared_login":
        technique_id = VALID_ACCOUNTS
        via = None  # a login has no CVE
    else:
        source_data = graph.nodes[source]
        source_cve = worst_exploitable_cve(graph, source)
        is_public_web_server = source_data["type"] == "web_server" and source_data["is_entry_point"]

        if is_public_web_server and source_cve:
            # the attacker breaks into the public web server itself, then moves on
            technique_id = PUBLIC_APP
            via = source_cve["cve"]
        else:
            technique_id = REMOTE_SERVICES
            via = worst_exploitable_cve(graph, target)["cve"]

    return {
        "from": source,
        "to": target,
        "technique_id": technique_id,
        "technique_name": techniques[technique_id]["name"],
        "via": via,
    }


def find_attack_paths(graph, techniques=None, max_length=MAX_PATH_LENGTH):
    """Find every attack path from an entry point to a sensitive machine.
    Returns a list in the "paths" shape of Contract 2:
        [{"nodes": [1, 3, 4], "steps": [{"from": 1, "to": 3, ...}, ...]}, ...]
    Call vuln_matcher.attach_vulnerabilities(graph) first, so machines have their CVEs."""
    if techniques is None:
        techniques = load_techniques()

    # 1. Keep only the moves the attacker is able to make
    moves = nx.DiGraph()
    moves.add_nodes_from(graph.nodes)
    moves.add_edges_from((u, v) for u, v in graph.edges if can_move(graph, u, v))

    entry_points = sorted(n for n, data in graph.nodes(data=True) if data["is_entry_point"])
    targets = sorted(n for n, data in graph.nodes(data=True) if data["is_sensitive"])

    # 2. Find every simple path from each entry point to each sensitive machine
    paths = []
    for entry in entry_points:
        for target in targets:
            if entry == target:
                continue  # the attacker already starts here, so there is no path to show
            for nodes in nx.all_simple_paths(moves, entry, target, cutoff=max_length):
                steps = [label_step(graph, u, v, techniques) for u, v in zip(nodes, nodes[1:])]
                paths.append({"nodes": nodes, "steps": steps})

    # Same order every time
    paths.sort(key=lambda path: path["nodes"])
    return paths
