"""vuln_matcher.py - attach known vulnerabilities (CVEs) to each machine.

For every machine we look at its software name and version, and find the CVEs
in data/vuln_db.json that affect that exact software and version.

SAFETY: this file only reads a local file. It makes no network calls.
(A live lookup to the NVD website could be added later as a separate, optional step.)
"""
import json
import re
from pathlib import Path

# The vulnerability list lives in backend/data/vuln_db.json
DB_PATH = Path(__file__).parent.parent / "data" / "vuln_db.json"

# Every entry in the file must have these fields
REQUIRED_FIELDS = ["cve", "software", "cvss", "description"]


class VulnDatabaseError(ValueError):
    """A problem with vuln_db.json. The message is safe to show to the user."""


def load_vuln_db(path=DB_PATH):
    """Read vuln_db.json and check it. Returns a list of entries."""
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise VulnDatabaseError(f"Vulnerability file not found: {path}")
    except json.JSONDecodeError as error:
        raise VulnDatabaseError(f"vuln_db.json is not valid JSON: {error}")

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise VulnDatabaseError("vuln_db.json must have a 'vulnerabilities' list.")

    for number, entry in enumerate(data["vulnerabilities"], start=1):
        for field in REQUIRED_FIELDS:
            if field not in entry:
                raise VulnDatabaseError(f"vuln_db.json entry {number} is missing '{field}'.")
        cvss = entry["cvss"]
        if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10:
            raise VulnDatabaseError(f"vuln_db.json entry {number} ({entry['cve']}): cvss must be a number from 0 to 10.")

    return data["vulnerabilities"]


def _version_tuple(text):
    """Turn a version like '2.4.49' into numbers (2, 4, 49) so we can compare them.
    Any text is ignored, so '21H2' becomes (21, 2). No digits gives ()."""
    return tuple(int(part) for part in re.findall(r"\d+", text or ""))


def version_in_range(version, min_version=None, max_version=None):
    """Is `version` between min_version and max_version? Both ends are included."""
    number = _version_tuple(version)
    if not number:
        return False  # we cannot tell, so we do not guess

    low = _version_tuple(min_version)
    high = _version_tuple(max_version) if max_version else None

    # Pad with zeros so (2, 0) and (2, 0, 0) count as the same version
    size = max(len(number), len(low), len(high or ()))
    pad = lambda numbers: numbers + (0,) * (size - len(numbers))

    if pad(number) < pad(low):
        return False
    if high is not None and pad(number) > pad(high):
        return False
    return True


def find_vulnerabilities(software, version, vuln_db):
    """Return the CVEs that affect this software and version, worst first.
    Each one has the 3 fields from Contract 1: cve, cvss, description."""
    name = (software or "").strip().lower()
    if not name:
        return []  # a machine with no software has nothing to match

    found = []
    for entry in vuln_db:
        if entry["software"].strip().lower() != name:
            continue
        if version_in_range(version, entry.get("min_version"), entry.get("max_version")):
            found.append({"cve": entry["cve"], "cvss": entry["cvss"], "description": entry["description"]})

    found.sort(key=lambda item: item["cvss"], reverse=True)
    return found


def attach_vulnerabilities(graph, vuln_db=None):
    """Fill in the 'vulnerabilities' list of every machine in the graph.
    Changes the graph in place and also returns it."""
    if vuln_db is None:
        vuln_db = load_vuln_db()

    for _, data in graph.nodes(data=True):
        data["vulnerabilities"] = find_vulnerabilities(data["software"], data["version"], vuln_db)
    return graph
