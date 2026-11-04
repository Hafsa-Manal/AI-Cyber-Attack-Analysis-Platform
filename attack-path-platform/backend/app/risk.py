"""risk.py - give every machine a risk score from 0 to 10 and rank the weak points.

HOW THE SCORE WORKS (the points always add up to at most 10):
  up to 7 points  HOW EASY IT IS TO BREAK IN.
                  This is 0.7 x the worst CVSS score on the machine.
                  If the attacker enters it with a shared login, it counts as at least 5.0,
                  because a stolen login works even when the machine has no flaw.
  up to 2 points  HOW MANY ATTACK PATHS GO THROUGH IT.
                  2 x (paths through the machine / all paths).
  1 point         IS IT SENSITIVE? Sensitive machines are what the attacker wants.

LEVELS: critical (8 and up), high (6 and up), medium (3 and up), low (below 3).

You can change the numbers below to tune the scoring.
Machines with a score of 0 are left out, because they are not weak points.

SAFETY: this is just arithmetic on data in memory. No network calls.
"""

VULN_WEIGHT = 0.7  # 10 x 0.7 = at most 7 points
PATH_WEIGHT = 2.0  # at most 2 points
SENSITIVE_BONUS = 1.0  # 1 point
LOGIN_EXPOSURE = 5.0  # a shared login counts like a medium flaw

# (lowest score, level name), checked from the top
LEVELS = [(8.0, "critical"), (6.0, "high"), (3.0, "medium")]


def risk_level(score):
    """Turn a score into a level name."""
    for lowest_score, name in LEVELS:
        if score >= lowest_score:
            return name
    return "low"


def _entered_by_shared_login(graph, paths):
    """The machines that the attacker enters with a shared login on some attack path."""
    entered = set()
    for path in paths:
        for step in path["steps"]:
            if graph.edges[step["from"], step["to"]]["connection"] == "shared_login":
                entered.add(step["to"])
    return entered


def rank_risks(graph, paths):
    """Score every machine. Returns the "risks" list of Contract 2, highest score first,
    but without the "explanation" (explain.py adds that):
        [{"node": 3, "score": 8.9, "level": "critical"}, ...]
    Needs the graph with its CVEs attached, and the paths from attacker.find_attack_paths()."""
    login_nodes = _entered_by_shared_login(graph, paths)

    risks = []
    for node_id, data in graph.nodes(data=True):
        # 1. how easy is it to break in? (0 to 10)
        break_in = max((v["cvss"] for v in data["vulnerabilities"]), default=0.0)
        if node_id in login_nodes:
            break_in = max(break_in, LOGIN_EXPOSURE)

        # 2. what share of the attack paths go through this machine? (0 to 1)
        if paths:
            share = sum(1 for path in paths if node_id in path["nodes"]) / len(paths)
        else:
            share = 0.0

        # 3. add it all up
        score = VULN_WEIGHT * break_in + PATH_WEIGHT * share
        if data["is_sensitive"]:
            score += SENSITIVE_BONUS
        score = round(score, 1)

        if score > 0:
            risks.append({"node": node_id, "score": score, "level": risk_level(score)})

    # highest score first. If two scores are equal, the lower id comes first
    risks.sort(key=lambda risk: (-risk["score"], risk["node"]))
    return risks
