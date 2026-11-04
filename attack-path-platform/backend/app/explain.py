"""explain.py - write a plain-English explanation and a fix for each risky machine.

Stage 1: simple text templates. We fill in the blanks with real facts from the graph
(names, CVEs, paths), so every sentence is true and easy to follow.
(Stage 2, later: an optional LLM could write nicer text.)

SAFETY: this only builds text from data in memory. No network calls.
"""
from app.attacker import PUBLIC_APP  # "T1190": the technique used against a public web server

MAX_FIX_ACTIONS = 3  # keep each fix short


def _join_names(names):
    """['A'] -> 'A'    ['A', 'B'] -> 'A and B'    ['A', 'B', 'C'] -> 'A, B and C'"""
    names = list(names)
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def _severity(cvss):
    """Word for a CVSS score, using the usual CVSS bands."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _add_unique(items, value):
    """Add to a list only if it is not there yet (keeps the order)."""
    if value not in items:
        items.append(value)


def _facts(graph, paths, node_id):
    """Collect the facts about one machine that the templates need."""
    data = graph.nodes[node_id]
    through = [p for p in paths if node_id in p["nodes"]]  # the paths that include this machine

    login_sources = []  # machines the attacker logs in from (shared login)
    network_sources = []  # machines the attacker attacks from (over the network)
    ports = []
    techniques = []  # MITRE ATT&CK techniques used against this machine
    goals = set()  # sensitive machines the attacker can reach after this one

    for path in through:
        position = path["nodes"].index(node_id)
        for later in path["nodes"][position + 1 :]:
            if graph.nodes[later]["is_sensitive"]:
                goals.add(later)

        for step in path["steps"]:
            edge = graph.edges[step["from"], step["to"]]
            source_name = graph.nodes[step["from"]]["name"]

            if step["to"] == node_id:
                if edge["connection"] == "shared_login":
                    _add_unique(login_sources, source_name)
                else:
                    _add_unique(network_sources, source_name)
                    _add_unique(ports, edge["port"])

            # T1190 is written on the step that LEAVES the web server it exploits
            used_against_this_machine = (
                step["to"] == node_id and step["technique_id"] != PUBLIC_APP
            ) or (step["from"] == node_id and step["technique_id"] == PUBLIC_APP)
            if used_against_this_machine:
                _add_unique(techniques, f"{step['technique_id']} {step['technique_name']}")

    return {
        "name": data["name"],
        "software": f"{data['software']} {data['version']}".strip(),
        "vulnerabilities": data["vulnerabilities"],
        "is_entry_point": data["is_entry_point"],
        "is_sensitive": data["is_sensitive"],
        "through": len(through),
        "login_sources": login_sources,
        "network_sources": network_sources,
        "ports": sorted(ports),
        "techniques": techniques,
        "goals": [graph.nodes[n]["name"] for n in sorted(goals)],
    }


def explain_risk(graph, paths, node_id):
    """Plain-English explanation for one machine."""
    f = _facts(graph, paths, node_id)
    sentences = []

    # 1. The machine's own weakness
    flaws = f["vulnerabilities"]
    if not flaws:
        sentences.append(f"{f['name']} has no known flaws in our vulnerability list.")
    else:
        worst = max(flaws, key=lambda v: v["cvss"])
        severity = _severity(worst["cvss"])
        if len(flaws) == 1:
            sentences.append(
                f"{f['name']} runs {f['software']}, which has a {severity}-severity known flaw "
                f"({worst['cve']}, CVSS {worst['cvss']})."
            )
        else:
            sentences.append(
                f"{f['name']} runs {f['software']}, which has {len(flaws)} known flaws. "
                f"The most serious is {worst['cve']} ({severity} severity, CVSS {worst['cvss']})."
            )
        sentences.append(f"Short description: {worst['description']}")

    # 2. How many attack paths use it
    total = len(paths)
    if total == 0:
        sentences.append("No attack path was found in this network, so this score comes only from the machine itself.")
    elif f["through"] == 0:
        sentences.append("No attack path goes through this machine.")
    elif f["through"] == total and total == 1:
        sentences.append("The only attack path goes through it.")
    elif f["through"] == total:
        sentences.append(f"Every attack path ({total} of {total}) goes through it, so it is a key point to protect.")
    else:
        sentences.append(f"It is on {f['through']} of the {total} attack paths.")

    # 3. The role it plays
    if f["is_sensitive"]:
        sentences.append("It is a sensitive machine, so reaching it is the attacker's goal.")
    if f["is_entry_point"]:
        sentences.append("It is an entry point, so an attacker can start here.")
    if f["goals"]:
        sentences.append(f"From here the attacker can reach {_join_names(f['goals'])}.")
    if f["login_sources"]:
        sentences.append(
            f"An attacker can log in to it from {_join_names(f['login_sources'])} "
            "with a shared login, which does not need any flaw."
        )

    # 4. The MITRE ATT&CK techniques
    if f["techniques"]:
        sentences.append(f"MITRE ATT&CK technique used here: {_join_names(f['techniques'])}.")

    return " ".join(sentences)


def suggest_fix(graph, paths, node_id):
    """A short fix for one machine, made of up to 3 actions."""
    f = _facts(graph, paths, node_id)
    actions = []

    flaws = sorted(f["vulnerabilities"], key=lambda v: v["cvss"], reverse=True)
    if flaws:
        cves = _join_names([v["cve"] for v in flaws[:3]])
        actions.append(f"Update {f['software']} to the latest patched version to fix {cves}.")

    if f["login_sources"]:
        actions.append(
            f"Stop sharing logins with {_join_names(f['login_sources'])}: "
            f"give {f['name']} its own password and turn on multi-factor login."
        )

    if f["network_sources"] and f["ports"]:
        port_word = "port" if len(f["ports"]) == 1 else "ports"
        port_text = _join_names([str(p) for p in f["ports"]])
        actions.append(
            f"Block {port_word} {port_text} on {f['name']} from "
            f"{_join_names(f['network_sources'])} unless it is really needed."
        )

    if f["is_entry_point"]:
        actions.append(
            f"Keep {f['name']} apart from the internal network, for example in its own "
            "network zone (DMZ), because it is open to attackers."
        )

    if f["is_sensitive"]:
        actions.append(
            f"Allow access to {f['name']} only for the people and machines that need it, "
            "and turn on logging so strange activity is noticed."
        )

    if not actions:
        actions.append(f"Keep {f['name']} up to date and limit who can connect to it.")

    return " ".join(actions[:MAX_FIX_ACTIONS])


def explain_all(graph, paths, risks):
    """Add an explanation to every risk and write a fix for it.
    Returns (risks, fixes), the "risks" and "fixes" lists of Contract 2.
    The risks you pass in are not changed."""
    explained = []
    fixes = []
    for risk in risks:
        node_id = risk["node"]
        explained.append(
            {
                "node": node_id,
                "score": risk["score"],
                "level": risk["level"],
                "explanation": explain_risk(graph, paths, node_id),
            }
        )
        fixes.append({"node": node_id, "fix": suggest_fix(graph, paths, node_id)})
    return explained, fixes
