"""vuln_matcher.py - attach known vulnerabilities (CVEs) to each machine.

Two sources of CVEs:
  1. LOCAL (always on):  data/vuln_db.json. No network needed.
  2. LIVE  (optional):   the NVD website's API. Used only when live=True.

HOW THE LIVE LOOKUP WORKS
  - Only for software we know how to name for NVD (see CPE_PRODUCTS below).
    Other software uses the local list only.
  - Only the public software name and version are sent to NVD. Never machine names,
    never IP addresses, never your files.
  - Answers are saved in data/nvd_cache.json for 7 days, so we ask NVD less often.
    You can delete that file at any time.
  - NVD allows only 5 requests per 30 seconds without a key, so we wait about 6 seconds
    between requests. A free key makes it faster: set the NVD_API_KEY environment variable.
    Request one at https://nvd.nist.gov/developers/request-an-api-key
  - If NVD does not answer, we raise NvdError (we never pretend the lookup worked).

SAFETY: the only address this file may contact is the NVD API.
"""
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

logger = logging.getLogger(__name__)

# ---------- local list ----------
DB_PATH = Path(__file__).parent.parent / "data" / "vuln_db.json"
REQUIRED_FIELDS = ["cve", "software", "cvss", "description"]

# ---------- live NVD lookup ----------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # the ONLY address we contact
NVD_CACHE_PATH = Path(__file__).parent.parent / "data" / "nvd_cache.json"
CACHE_DAYS = 7
RESULTS_PER_PAGE = 200  # how many CVEs we ask NVD for, per software version
MAX_LIVE_CVES_PER_MACHINE = 10  # we keep the 10 worst
MAX_DESCRIPTION_LENGTH = 200
REQUEST_TIMEOUT = 30  # seconds
MIN_GAP_NO_KEY = 6.1  # seconds between requests without a key
MIN_GAP_WITH_KEY = 0.7  # seconds between requests with a key
RETRY_WAIT_SECONDS = 30  # wait before trying again when NVD says "too many requests"
MAX_RETRIES = 2

# Software names we can turn into an NVD name (called a CPE). Format: "vendor:product".
# Anything not in this list (for example Windows) is checked against the local list only.
CPE_PRODUCTS = {
    "apache": "apache:http_server",
    "apache http server": "apache:http_server",
    "apache log4j": "apache:log4j",
    "apache tomcat": "apache:tomcat",
    "samba": "samba:samba",
    "mysql": "oracle:mysql",
    "postgresql": "postgresql:postgresql",
    "openssh": "openbsd:openssh",
    "php": "php:php",
    "wordpress": "wordpress:wordpress",
    "mongodb": "mongodb:mongodb",
    "node.js": "nodejs:node.js",
    "microsoft office": "microsoft:office",
}

_nvd_lock = threading.Lock()  # one NVD request at a time
_last_request_at = 0.0  # when we last asked NVD


class VulnDatabaseError(ValueError):
    """A problem with vuln_db.json. The message is safe to show to the user."""


class NvdError(ValueError):
    """The live NVD lookup failed. The message is safe to show to the user."""


class _TryAgain(Exception):
    """NVD is busy or slow. Waiting and asking again may work."""


# =====================================================================
# Part 1: the local list
# =====================================================================
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


# =====================================================================
# Part 2: the live NVD lookup (optional)
# =====================================================================
def cpe_name(software, version):
    """Turn a software name and version into the name NVD uses, like
    'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'.
    Returns None if we do not know how (then no live lookup is done)."""
    product = CPE_PRODUCTS.get((software or "").strip().lower())
    version = (version or "").strip().lower()
    # the version must look like 2.4.49. This also keeps odd characters out of the web address
    if not product or not re.fullmatch(r"\d[a-z0-9._-]*", version):
        return None
    return f"cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*"


def _best_cvss(metrics):
    """Pick one CVSS score from the NVD 'metrics' of a CVE. Newer scoring versions come first.
    Returns None if the CVE has no score yet."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            # "Primary" is the score NVD itself gave. Use it if there is one.
            chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            try:
                return float(chosen["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def _short_description(descriptions):
    """The English description, cut down to its first sentence (at most 200 characters)."""
    text = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    text = " ".join(text.split())  # remove line breaks and extra spaces
    if not text:
        return "No description available."
    end = text.find(". ")
    if end != -1:
        text = text[: end + 1]
    if len(text) > MAX_DESCRIPTION_LENGTH:
        text = text[: MAX_DESCRIPTION_LENGTH - 3].rstrip() + "..."
    return text


def parse_nvd_response(data):
    """Turn an NVD answer into our CVE list (cve, cvss, description), worst first.
    CVEs without a score, and rejected CVEs, are left out."""
    found = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected" or "id" not in cve:
            continue
        score = _best_cvss(cve.get("metrics", {}))
        if score is None:
            continue
        found.append({"cve": cve["id"], "cvss": score, "description": _short_description(cve.get("descriptions", []))})
    found.sort(key=lambda item: item["cvss"], reverse=True)
    return found


def _wait_for_turn(gap):
    """Wait until at least `gap` seconds have passed since the last NVD request."""
    global _last_request_at
    wait = _last_request_at + gap - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def _download_once(url, api_key):
    """Ask NVD one time and return the answer as a dict."""
    # SAFETY: the only address this program may contact is the NVD API
    if not url.startswith(NVD_URL + "?"):
        raise NvdError("Refusing to contact any address other than the NVD API.")

    headers = {"Accept": "application/json", "User-Agent": "attack-path-simulator (college project)"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code in (403, 429, 503):
            raise _TryAgain(f"HTTP {error.code}")  # NVD says "too many requests" or "busy"
        if error.code == 404:
            logger.info("NVD answered 404 (nothing found) for %s", url)
            return {"vulnerabilities": []}
        raise NvdError(f"NVD answered with error {error.code}.")
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise _TryAgain("timeout")
        raise NvdError("Cannot reach NVD. Check your internet connection.")
    except TimeoutError:
        raise _TryAgain("timeout")
    except json.JSONDecodeError:
        raise NvdError("NVD sent a reply that is not valid JSON.")


def _request_nvd(url):
    """Ask NVD politely: one request at a time, with pauses, and try again if it is busy."""
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    gap = MIN_GAP_WITH_KEY if api_key else MIN_GAP_NO_KEY

    with _nvd_lock:
        for attempt in range(MAX_RETRIES + 1):
            _wait_for_turn(gap)
            try:
                return _download_once(url, api_key)
            except _TryAgain as problem:
                if attempt == MAX_RETRIES:
                    raise NvdError(
                        f"NVD is busy or did not answer ({problem}). "
                        "Wait a minute and try again. Results already fetched are saved."
                    )
                time.sleep(RETRY_WAIT_SECONDS)


def _load_cache(path):
    """Read the saved NVD answers. A missing or broken file just means an empty cache."""
    try:
        with open(path, encoding="utf-8") as file:
            cache = json.load(file)
        return cache if isinstance(cache, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(path, cache):
    """Save the NVD answers. The cache is only a speed-up, so a failure is not an error."""
    try:
        path = Path(path)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        os.replace(temp, path)
    except OSError as error:
        logger.warning("Could not save the NVD cache: %s", error)


def _is_fresh(entry):
    """Was this saved answer fetched in the last 7 days?"""
    try:
        fetched = datetime.fromisoformat(entry["fetched_at"])
        return datetime.now(timezone.utc) - fetched < timedelta(days=CACHE_DAYS)
    except (KeyError, TypeError, ValueError):
        return False


def lookup_nvd(software, version):
    """Ask NVD which CVEs affect this software and version (the 10 worst).
    Returns [] for software we cannot name for NVD. Raises NvdError if NVD fails."""
    cpe = cpe_name(software, version)
    if cpe is None:
        return []

    cache = _load_cache(NVD_CACHE_PATH)
    entry = cache.get(cpe)
    if isinstance(entry, dict) and _is_fresh(entry):
        return entry["vulnerabilities"]

    # "isVulnerable" means: only CVEs where this software is the vulnerable part
    url = f"{NVD_URL}?cpeName={quote(cpe, safe=':*')}&isVulnerable&resultsPerPage={RESULTS_PER_PAGE}"
    found = parse_nvd_response(_request_nvd(url))[:MAX_LIVE_CVES_PER_MACHINE]

    cache[cpe] = {"fetched_at": datetime.now(timezone.utc).isoformat(), "vulnerabilities": found}
    _save_cache(NVD_CACHE_PATH, cache)
    return found


def _merge(local, live):
    """Combine both lists. If a CVE is in both, our local entry wins. Worst first."""
    merged = {item["cve"]: item for item in live}
    merged.update({item["cve"]: item for item in local})
    return sorted(merged.values(), key=lambda item: item["cvss"], reverse=True)


# =====================================================================
# Part 3: attach to the graph
# =====================================================================
def attach_vulnerabilities(graph, vuln_db=None, live=False):
    """Fill in the 'vulnerabilities' list of every machine in the graph.
    live=True also asks NVD (slower, needs internet).
    Changes the graph in place and also returns it."""
    if vuln_db is None:
        vuln_db = load_vuln_db()

    for _, data in graph.nodes(data=True):
        found = find_vulnerabilities(data["software"], data["version"], vuln_db)
        if live:
            found = _merge(found, lookup_nvd(data["software"], data["version"]))
        data["vulnerabilities"] = found
    return graph
