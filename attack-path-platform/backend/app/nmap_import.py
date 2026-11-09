"""nmap_import.py - turn an Nmap XML scan file into DRAFT nodes.csv and edges.csv.

The user runs Nmap themselves, on a network they own or have permission to scan:
    nmap -sV -oX scan.xml <their lab network>
and uploads scan.xml. This file only READS that file. It never runs Nmap and never
connects to anything.

A scan shows machines, open ports and programs. It does NOT show who connects to whom,
shared logins, or what is really sensitive. So everything we add is a GUESS, and we
return a list of our guesses so the user can check them.

What we guess:
  - machine type, from the open ports (3306 = database, 80/443 = web server ...)
  - entry point:  port 80 or 443 is open
  - sensitive:    a database port is open
  - connections:  entry points -> other machines -> sensitive machines
Only ONE program per machine fits in nodes.csv, so we pick the most important one.

IP addresses and MAC addresses are never copied into the draft files.

SAFETY: the XML is read with defusedxml, which refuses dangerous XML tricks.
"""
import csv
import io
import re
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET

MAX_MACHINES = 100  # more than this is too big to review by hand

# What the open ports tell us
WEB_PORTS = {80, 443}
DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379}
DB_SERVICES = {"mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis"}
FILE_PORTS = {21, 139, 445, 2049}
FILE_SERVICES = {"netbios-ssn", "microsoft-ds", "nfs", "ftp"}
PRINTER_PORTS = {631, 9100}

# Which program is the "main" one on a machine (first in this list wins)
PRIORITY = ["database", "web", "http", "file", "printer", "remote", "other", "ssh"]

# The machine type for each kind of main program. Anything else is "server".
TYPE_BY_KIND = {
    "database": "database",
    "web": "web_server",
    "http": "app_server",
    "file": "file_server",
    "printer": "printer",
    "remote": "workstation",
}

# Nmap's product names -> the names our vulnerability lists use
PRODUCT_NAMES = {
    "apache httpd": "Apache",
    "apache tomcat": "Apache Tomcat",
    "apache tomcat/coyote jsp engine": "Apache Tomcat",
    "samba smbd": "Samba",
    "mysql": "MySQL",
    "postgresql db": "PostgreSQL",
    "openssh": "OpenSSH",
    "node.js express framework": "Node.js",
}

VERSION_PATTERN = re.compile(r"\d[\w.\-]*")  # like 2.4.49. Not "3.X - 4.X"


class NmapImportError(ValueError):
    """A problem with the Nmap file. The message is safe to show to the user."""


def _clean(text, limit=40):
    """Make text safe for a CSV file: only letters, digits, spaces and . _ -
    and never starting with a character that Excel could treat as a formula."""
    text = re.sub(r"[^\w .\-]", " ", text or "")
    text = " ".join(text.split())
    return text.lstrip(" .-_")[:limit].strip()


def _count(number, word):
    return f"{number} {word}" + ("" if number == 1 else "s")


def _parse(source):
    """Read the XML file safely. `source` is a file path or an open file."""
    try:
        root = SafeET.parse(source).getroot()
    except DefusedXmlException:
        raise NmapImportError(
            "The file uses XML features that are not allowed for safety. "
            "Please upload the plain file made by: nmap -sV -oX scan.xml <target>"
        )
    except (ParseError, UnicodeDecodeError):
        raise NmapImportError("The file is not valid XML. Please upload the file made by: nmap -sV -oX scan.xml <target>")
    except OSError:
        raise NmapImportError("The file could not be read.")

    if root.tag != "nmaprun":
        raise NmapImportError(
            "This does not look like an Nmap XML file. Make one with: nmap -sV -oX scan.xml <your lab network>"
        )
    return root


def _read_host(host):
    """Read one <host>. Returns None if it is down or has no open ports."""
    status = host.find("status")
    if status is None or status.get("state") != "up":
        return None

    ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue  # closed and filtered ports do not count
        try:
            number = int(port.get("portid"))
        except (TypeError, ValueError):
            continue
        if not 1 <= number <= 65535:
            continue
        service = port.find("service")
        attributes = service.attrib if service is not None else {}
        ports.append(
            {
                "number": number,
                "service": (attributes.get("name") or "").lower(),
                "product": (attributes.get("product") or "").strip(),
                "version": (attributes.get("version") or "").strip(),
            }
        )
    if not ports:
        return None

    hostname = ""
    for item in host.findall("hostnames/hostname"):  # we use the name, never the IP address
        if item.get("name"):
            hostname = item.get("name")
            break
    return {"hostname": hostname, "ports": ports}


def _kind(port):
    """What kind of program is on this port?"""
    number, service = port["number"], port["service"]
    if number in DB_PORTS or service in DB_SERVICES:
        return "database"
    if number in WEB_PORTS:
        return "web"
    if service.startswith("http"):
        return "http"
    if number in FILE_PORTS or service in FILE_SERVICES:
        return "file"
    if number in PRINTER_PORTS or service == "ipp":
        return "printer"
    if number == 3389 or service == "ms-wbt-server":
        return "remote"
    if number == 22 or service == "ssh":
        return "ssh"
    return "other"


def _unique_name(name, used):
    """Give every machine its own name (web01, web01 2, web01 3 ...)."""
    candidate, number = name, 2
    while candidate.lower() in used:
        candidate = f"{name} {number}"
        number += 1
    used.add(candidate.lower())
    return candidate


def _describe(raw, number, used_names):
    """Turn one scanned host into a machine for nodes.csv. Returns (machine, notes)."""
    notes = []
    name = _unique_name(_clean(raw["hostname"]) or f"Host {number}", used_names)

    # the main program: the most important one on the machine
    ports = sorted(raw["ports"], key=lambda p: (PRIORITY.index(_kind(p)), p["number"]))
    main = ports[0]
    kinds = {_kind(p) for p in raw["ports"]}

    # software and version
    product = main["product"]
    software = PRODUCT_NAMES.get(product.lower(), _clean(product))
    version = main["version"]
    if not software:
        version = ""
        notes.append(f"{name}: Nmap could not tell what program runs on port {main['number']}, so the software is blank.")
    elif not VERSION_PATTERN.fullmatch(version):
        if version:
            notes.append(f"{name}: the version of {software} is unclear ('{version}'), so it is left blank.")
        else:
            notes.append(f"{name}: Nmap did not report the version of {software}, so it is left blank.")
        version = ""

    # other programs we had to leave out
    left_out = []
    for port in ports[1:]:
        if port["product"] and (port["product"], port["version"]) != (main["product"], main["version"]):
            text = f"{port['product']} {port['version']}".strip()
            if text not in left_out:
                left_out.append(text)
    if left_out:
        notes.append(
            f"{name} also runs {', '.join(left_out[:3])}. Only the main program of each machine can be "
            "listed, so the rest were left out."
        )

    machine = {
        "name": name,
        "type": TYPE_BY_KIND.get(_kind(main), "server"),
        "software": software,
        "version": version,
        "entry": "web" in kinds,
        "sensitive": "database" in kinds,
        "port": main["number"],
    }
    return machine, notes


def _make_edges(machines):
    """Guess the connections: entry points -> other machines -> sensitive machines."""
    entries = [m for m in machines if m["entry"]]
    sensitive = [m for m in machines if m["sensitive"]]
    middle = [m for m in machines if not m["entry"] and not m["sensitive"]]

    edges = []
    for entry in entries:
        for other in middle:
            edges.append((entry["id"], other["id"], "network_access", other["port"]))
    for other in middle:
        for target in sensitive:
            edges.append((other["id"], target["id"], "db_access", target["port"]))
    if not middle:  # nothing in between, so entry points connect to sensitive machines directly
        for entry in entries:
            for target in sensitive:
                if entry is not target:
                    edges.append((entry["id"], target["id"], "db_access", target["port"]))
    return edges


def _to_csv(header, rows):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue()


def import_nmap(source):
    """Read an Nmap XML file and return a draft:
        {"nodes_csv": "...", "edges_csv": "...", "guesses": ["...", ...]}
    The two CSV texts follow the same format as the files in docs/contracts.md.
    Raises NmapImportError if the file has a problem."""
    root = _parse(source)

    raw_hosts = [_read_host(host) for host in root.findall("host")]
    scanned = [raw for raw in raw_hosts if raw is not None]
    skipped = len(raw_hosts) - len(scanned)
    if not scanned:
        raise NmapImportError("The scan has no machine that is up and has an open port.")
    if len(scanned) > MAX_MACHINES:
        raise NmapImportError(
            f"The scan has {len(scanned)} machines. The limit is {MAX_MACHINES}. Please scan a smaller network."
        )

    # 1. machines
    machines, machine_notes, used_names = [], [], set()
    for number, raw in enumerate(scanned, start=1):
        machine, notes = _describe(raw, number, used_names)
        machine["id"] = number
        machines.append(machine)
        machine_notes.extend(notes)

    # 2. connections
    edges = _make_edges(machines)

    # 3. the files
    nodes_csv = _to_csv(
        ["id", "name", "type", "software", "version", "is_entry_point", "is_sensitive"],
        [
            [m["id"], m["name"], m["type"], m["software"], m["version"],
             "yes" if m["entry"] else "no", "yes" if m["sensitive"] else "no"]
            for m in machines
        ],
    )
    edges_csv = _to_csv(["source", "target", "connection", "port"], edges)

    # 4. the list of guesses
    guesses = [f"Found {_count(len(machines), 'machine')} that are up and have open ports."]
    if skipped:
        guesses.append(f"Skipped {_count(skipped, 'host')} (down, or no open ports).")
    guesses.append("Machine types are guessed from the open ports.")

    entry_names = [m["name"] for m in machines if m["entry"]]
    if entry_names:
        guesses.append(f"Entry points (guess: port 80 or 443 is open): {', '.join(entry_names)}.")
    else:
        guesses.append(
            "No entry point was found, because no machine has port 80 or 443 open. "
            "Set is_entry_point to yes for at least one machine by hand."
        )
    sensitive_names = [m["name"] for m in machines if m["sensitive"]]
    if sensitive_names:
        guesses.append(f"Sensitive machines (guess: a database port is open): {', '.join(sensitive_names)}.")
    else:
        guesses.append(
            "No sensitive machine was found, because no database port is open. "
            "Set is_sensitive to yes for at least one machine by hand."
        )

    if all(not m["software"] for m in machines):
        guesses.append("No program names were found. Run Nmap again with -sV to detect programs and versions.")
    guesses.extend(machine_notes)

    if edges:
        guesses.append(
            "Connections are a guess: entry points to other machines, then to sensitive machines. "
            "A scan cannot show who really connects to whom, so please check edges.csv."
        )
    else:
        guesses.append("No connections could be drawn. Add rows to edges.csv by hand.")
    guesses.append("Shared logins cannot be seen in a scan, so none were added.")
    guesses.append("IP addresses and MAC addresses were not copied into the files.")

    return {"nodes_csv": nodes_csv, "edges_csv": edges_csv, "guesses": guesses}
