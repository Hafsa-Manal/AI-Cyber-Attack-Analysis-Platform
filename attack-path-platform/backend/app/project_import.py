"""project_import.py - read a project ZIP and make DRAFT nodes.csv and edges.csv.

Rule-based, no AI. We look at a short list of known files inside the zip and guess the
machines from them. Everything is a guess, so we also return a list of our guesses.

Files we read:   docker-compose.yml (and compose.yml), Dockerfile
Files we NEVER read: code, .env files (they hold secrets), keys, or anything else.

HOW THE GUESSES WORK
  - Every service in docker-compose.yml is one machine.
  - Software and version come from the image name (mysql:5.7.30), or from the FROM line of
    the service's Dockerfile.
  - Entry point: the service publishes a port (ports:).   Sensitive: it is a database.
  - Connections: depends_on, links, and service names used in environment variables.
    (If there are none, we guess: entry points -> other machines -> sensitive machines.)

SAFETY
  - We never write the zip to disk and never run anything from it. We read a few files
    into memory, with size limits (so zip bombs and huge files are refused).
  - Passwords and other values are never copied. We use only names, images and ports.
  - YAML is read with safe_load. Error messages never include text from the files.
"""
import posixpath
import re
import zipfile
import zlib

import yaml

# Shared with the Nmap importer, so both clean names for CSV the same way
from app.nmap_import import MAX_MACHINES, _clean, _count, _make_edges, _to_csv, _unique_name

# ---------- limits ----------
MAX_ENTRIES = 100_000  # files inside the zip
MAX_FILE_BYTES = 200_000  # one file we read
MAX_TOTAL_BYTES = 2_000_000  # all files we read together
MAX_FILES_READ = 100
MAX_DEPTH = 3  # folders deep (after removing the one outer folder)

# Folders we skip completely
IGNORED_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__", "__MACOSX", "dist", "build",
    "vendor", ".idea", ".vscode", "site-packages", ".next", "coverage",
}
ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template"}
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

# image name -> (software name, machine type, usual port). Names match our vulnerability lists.
IMAGE_INFO = {
    "mysql": ("MySQL", "database", 3306),
    "mysql-server": ("MySQL", "database", 3306),
    "mariadb": ("MariaDB", "database", 3306),
    "postgres": ("PostgreSQL", "database", 5432),
    "postgresql": ("PostgreSQL", "database", 5432),
    "mongo": ("MongoDB", "database", 27017),
    "mongodb": ("MongoDB", "database", 27017),
    "redis": ("Redis", "database", 6379),
    "nginx": ("nginx", "web_server", 80),
    "httpd": ("Apache", "web_server", 80),
    "apache": ("Apache", "web_server", 80),
    "wordpress": ("WordPress", "web_server", 80),
    "tomcat": ("Apache Tomcat", "app_server", 8080),
    "node": ("Node.js", "app_server", 3000),
    "php": ("PHP", "app_server", 80),
    "python": ("Python", "app_server", 8000),
}
TYPE_DEFAULT_PORT = {"web_server": 80, "app_server": 8080, "database": 3306, "server": 80}


class ProjectImportError(ValueError):
    """A problem with the project zip. The message is safe to show to the user."""


# =====================================================================
# Part 1: reading the zip safely
# =====================================================================
def _basename(path):
    return path.rsplit("/", 1)[-1]


def _is_dockerfile(name):
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _is_wanted(name):
    """The only files we read."""
    return name in COMPOSE_NAMES or _is_dockerfile(name)


def _safe_parts(filename):
    """Split a zip path into folders. Returns None for paths we refuse (.., absolute, drive letters)."""
    name = filename.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if ".." in parts:
        return None
    return parts


def _read_zip(source):
    """Read the wanted files into memory. Returns ({path: text}, [notes])."""
    try:
        archive = zipfile.ZipFile(source)
    except zipfile.BadZipFile:
        raise ProjectImportError("The file is not a valid zip file.")
    except OSError:
        raise ProjectImportError("The file could not be read.")

    with archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > MAX_ENTRIES:
            raise ProjectImportError(
                f"The zip has more than {MAX_ENTRIES} files. Please zip only your project, "
                "without folders like node_modules."
            )

        # the safe path of every file. Unsafe paths are dropped.
        entries = []
        for info in infos:
            parts = _safe_parts(info.filename)
            if parts and parts[0] != "__MACOSX":
                entries.append((parts, info))

        # if everything sits inside one outer folder (my-project/...), remove that folder
        outer = {parts[0] for parts, _ in entries}
        if len(outer) == 1 and all(len(parts) > 1 for parts, _ in entries):
            entries = [(parts[1:], info) for parts, info in entries]

        files, ignored, env_ignored, unreadable, too_big, total = {}, 0, 0, 0, 0, 0
        stopped = False
        for parts, info in entries:
            name = parts[-1]
            if name == ".env" or (name.startswith(".env.") and name not in ENV_EXAMPLES):
                env_ignored += 1  # never read: these hold secrets
                continue
            if any(part in IGNORED_DIRS for part in parts[:-1]) or len(parts) > MAX_DEPTH:
                ignored += 1
                continue
            if not _is_wanted(name):
                continue
            if info.flag_bits & 0x1:  # encrypted
                unreadable += 1
                continue
            if info.file_size > MAX_FILE_BYTES:
                too_big += 1
                continue
            if len(files) >= MAX_FILES_READ or total + info.file_size > MAX_TOTAL_BYTES:
                stopped = True
                continue
            try:
                with archive.open(info) as file:
                    data = file.read(MAX_FILE_BYTES + 1)  # never read more than the limit
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, EOFError, OSError):
                unreadable += 1
                continue
            if len(data) > MAX_FILE_BYTES:
                too_big += 1
                continue
            total += len(data)
            files["/".join(parts)] = data.decode("utf-8-sig", errors="replace")

    notes = []
    if ignored:
        notes.append(
            f"Ignored {_count(ignored, 'file')} in folders like node_modules and .git, "
            f"or nested more than {MAX_DEPTH} folders deep."
        )
    if env_ignored:
        notes.append(f"Ignored {_count(env_ignored, '.env file')}. We never read them, because they hold secrets.")
    if too_big:
        notes.append(f"Skipped {_count(too_big, 'file')} (too big, over {MAX_FILE_BYTES // 1000} KB).")
    if unreadable:
        notes.append(f"Skipped {_count(unreadable, 'file')} (encrypted or could not be read).")
    if stopped:
        notes.append("The zip has many config files, so some were not read.")
    return files, notes


# =====================================================================
# Part 2: images and Dockerfiles
# =====================================================================
def _image_facts(image):
    """What an image name tells us: software, version, machine type, usual port."""
    image = image.strip().split("@")[0]  # remove a digest like @sha256:...
    last = image.rsplit("/", 1)[-1]  # remove the registry and the owner
    repo, _, tag = last.partition(":")
    repo = repo.lower()

    if "$" in repo or not repo:
        return {"software": "", "version": "", "type": "server", "port": None, "tag": tag, "variable": True}

    software, machine_type, port = IMAGE_INFO.get(repo, (_clean(repo), "server", None))
    match = re.match(r"v?(\d+(?:\.\d+)*)", tag)
    return {
        "software": software,
        "version": match.group(1) if match else "",
        "type": machine_type,
        "port": port,
        "tag": tag,
        "variable": False,
    }


def _parse_dockerfile(text):
    """Returns (the image the container is finally built on, the ports from EXPOSE lines)."""
    stages = {}  # stage name -> image, for "FROM build" style lines
    final_image = ""
    ports = []
    for line in text.splitlines():
        words = line.split()
        if not words or words[0].startswith("#"):
            continue
        instruction = words[0].upper()
        if instruction == "FROM":
            rest = [w for w in words[1:] if not w.startswith("--")]
            if not rest:
                continue
            image = stages.get(rest[0].lower(), rest[0])
            if len(rest) >= 3 and rest[1].upper() == "AS":
                stages[rest[2].lower()] = image
            final_image = "" if image.lower() == "scratch" else image
        elif instruction == "EXPOSE":
            for word in words[1:]:
                match = re.match(r"\d+", word)
                port = _valid_port(match.group()) if match else None
                if port:
                    ports.append(port)
    return final_image, ports


# =====================================================================
# Part 3: docker-compose.yml
# =====================================================================
def _valid_port(number):
    try:
        number = int(number)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 65535 else None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _container_port(entry):
    """One entry of 'ports:' or 'expose:' -> the port inside the container, or None."""
    if isinstance(entry, dict):
        return _valid_port(entry.get("target"))
    text = str(entry).split("/")[0]  # remove "/tcp"
    match = re.match(r"\d+", text.split(":")[-1])  # the container side. A range gives its first number
    return _valid_port(match.group()) if match else None


def _env_values(service):
    """The VALUES of a service's environment variables. Only used to spot service names. Never output."""
    env = service.get("environment")
    if isinstance(env, dict):
        return [str(value) for value in env.values() if value is not None]
    if isinstance(env, list):
        return [item.split("=", 1)[1] for item in env if isinstance(item, str) and "=" in item]
    return []


def _mentions(value, alias):
    """Does this value point at the service called `alias`? (db, @db:5432, //db/, db:5432)"""
    if value.strip().lower() == alias:
        return True
    name = re.escape(alias)
    pattern = rf"(?:@|//){name}(?=[:/?\s]|$)|(?<![\w./@-]){name}:\d"
    return re.search(pattern, value, re.IGNORECASE) is not None


def _find_links(key, service, aliases):
    """The services that `key` connects to: depends_on, links, and names in environment values."""
    targets = []

    def add(alias):
        target = aliases.get(str(alias).strip().lower())
        if target and target != key and target not in targets:
            targets.append(target)

    depends = service.get("depends_on")
    for item in depends.keys() if isinstance(depends, dict) else _as_list(depends):
        add(item)
    for item in _as_list(service.get("links")):
        add(str(item).split(":")[0])
    for value in _env_values(service):
        for alias in aliases:
            if _mentions(value, alias):
                add(alias)
    return targets


def _build_dockerfile(build, compose_dir, files):
    """The text of the Dockerfile that `build:` points at, if it is in the zip."""
    if isinstance(build, dict):
        context, name = build.get("context", "."), build.get("dockerfile") or "Dockerfile"
    else:
        context, name = build, "Dockerfile"
    if not isinstance(context, str) or not isinstance(name, str) or "://" in context:
        return None
    path = posixpath.normpath(posixpath.join(compose_dir, context, name))
    if path.startswith("..") or path.startswith("/"):
        return None
    return files.get(path)


def _make_machine(name, facts, published, ports, default_type, notes):
    """Put the facts together into one machine (a dict)."""
    software = facts["software"] if facts else ""
    version = facts["version"] if facts else ""
    # a known image tells us the type. Otherwise we use the default (our own code = app_server)
    machine_type = facts["type"] if facts and facts["type"] != "server" else default_type

    port = ports[0] if ports else (facts["port"] if facts and facts["port"] else TYPE_DEFAULT_PORT[machine_type])

    if facts and facts["variable"]:
        notes.append(f"{name}: the image name uses a variable, so the software is blank.")
    elif software and not version:
        shown = f"tag '{facts['tag']}'" if facts["tag"] else "no tag"
        notes.append(f"{name}: the version of {software} is unclear ({shown}), so it is left blank.")

    sensitive = machine_type == "database"
    if sensitive and published:
        notes.append(f"{name}: this database publishes port {port} to the host. If that is not needed, remove it.")
    return {
        "name": name,
        "type": machine_type,
        "software": software,
        "version": version,
        "entry": bool(published),
        "sensitive": sensitive,
        "port": port,
    }


def _load_yaml(text, path):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        line = getattr(getattr(error, "problem_mark", None), "line", None)
        where = f" (around line {line + 1})" if line is not None else ""
        # we never show the YAML error text, because it can contain lines of the file
        raise ProjectImportError(f"{path} is not valid YAML{where}.")
    except (RecursionError, ValueError):
        raise ProjectImportError(f"{path} is not valid YAML.")


def _from_compose(paths, files):
    path = paths[0]
    notes = []
    if len(paths) > 1:
        notes.append(f"Several compose files were found. Only {path} was used.")

    data = _load_yaml(files[path], path)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict) or not services:
        raise ProjectImportError(f"{path} has no services.")
    if len(services) > MAX_MACHINES:
        raise ProjectImportError(f"{path} has {len(services)} services. The limit is {MAX_MACHINES}.")

    compose_dir = posixpath.dirname(path)
    machines, used_names, keys = [], set(), []
    for number, (key, raw) in enumerate(services.items(), start=1):
        service = raw if isinstance(raw, dict) else {}
        name = _unique_name(_clean(str(key)) or "service", used_names)

        facts, dockerfile_ports = None, []
        default_type = "server"
        build = service.get("build")
        if build:  # our own code: the Dockerfile tells us what it runs on
            default_type = "app_server"
            dockerfile = _build_dockerfile(build, compose_dir, files)
            if dockerfile is None:
                notes.append(f"{name}: its Dockerfile was not found in the zip, so the software is blank.")
            else:
                image, dockerfile_ports = _parse_dockerfile(dockerfile)
                if image:
                    facts = _image_facts(image)
                else:
                    notes.append(f"{name}: its Dockerfile has no usable FROM line, so the software is blank.")
        elif isinstance(service.get("image"), str):
            facts = _image_facts(service["image"])
        else:
            notes.append(f"{name}: no image or build was given, so the software is blank.")

        published = bool(_as_list(service.get("ports")))
        ports = [p for p in map(_container_port, _as_list(service.get("ports")) + _as_list(service.get("expose"))) if p]
        machine = _make_machine(name, facts, published, ports or dockerfile_ports, default_type, notes)
        machine["id"] = number
        machine["key"] = str(key)
        machine["container_name"] = service.get("container_name") if isinstance(service.get("container_name"), str) else None
        machines.append(machine)
        keys.append((str(key), service))

    # connections
    aliases = {}
    for machine in machines:
        aliases.setdefault(machine["key"].lower(), machine["key"])
        if machine["container_name"]:
            aliases.setdefault(machine["container_name"].lower(), machine["key"])
    by_key = {machine["key"]: machine for machine in machines}

    edges = []
    for key, service in keys:
        for target_key in _find_links(key, service, aliases):
            source, target = by_key[key], by_key[target_key]
            connection = "db_access" if target["type"] == "database" else "network_access"
            edges.append((source["id"], target["id"], connection, target["port"]))

    guessed = False
    if not edges and len(machines) > 1:
        edges, guessed = _make_edges(machines), True
    return {"machines": machines, "edges": edges, "guessed": guessed, "source": path, "notes": notes}


def _from_dockerfiles(paths, files):
    """No compose file: every Dockerfile is one machine."""
    if len(paths) > MAX_MACHINES:
        raise ProjectImportError(f"The zip has {len(paths)} Dockerfiles. The limit is {MAX_MACHINES}.")
    machines, notes, used_names = [], [], set()
    for number, path in enumerate(paths, start=1):
        folder = posixpath.basename(posixpath.dirname(path))
        name = _unique_name(_clean(folder) or "app", used_names)
        image, ports = _parse_dockerfile(files[path])
        facts = _image_facts(image) if image else None
        if facts is None:
            notes.append(f"{name}: its Dockerfile has no usable FROM line, so the software is blank.")
        machine = _make_machine(name, facts, bool(ports), ports, "app_server", notes)
        machine["id"] = number
        machines.append(machine)
    edges = _make_edges(machines)
    return {"machines": machines, "edges": edges, "guessed": bool(edges), "source": "the Dockerfiles", "notes": notes}


# =====================================================================
# Part 4: the draft
# =====================================================================
def import_project(source):
    """Read a project zip (a file path or an open file) and return a draft:
        {"nodes_csv": "...", "edges_csv": "...", "guesses": ["...", ...]}
    Raises ProjectImportError if the zip has a problem."""
    files, zip_notes = _read_zip(source)

    by_depth = lambda path: (path.count("/"), path)
    compose_paths = sorted((p for p in files if _basename(p) in COMPOSE_NAMES), key=by_depth)
    docker_paths = sorted((p for p in files if _is_dockerfile(_basename(p))), key=by_depth)

    if compose_paths:
        found = _from_compose(compose_paths, files)
    elif docker_paths:
        found = _from_dockerfiles(docker_paths, files)
    else:
        raise ProjectImportError(
            "No docker-compose.yml or Dockerfile was found in the zip. "
            "Use the AI helper prompt instead, or check that you zipped the project folder."
        )

    machines, edges = found["machines"], found["edges"]
    nodes_csv = _to_csv(
        ["id", "name", "type", "software", "version", "is_entry_point", "is_sensitive"],
        [
            [m["id"], m["name"], m["type"], m["software"], m["version"],
             "yes" if m["entry"] else "no", "yes" if m["sensitive"] else "no"]
            for m in machines
        ],
    )
    edges_csv = _to_csv(["source", "target", "connection", "port"], edges)

    guesses = [f"Read {found['source']}: found {_count(len(machines), 'machine')}."]
    guesses.extend(zip_notes)
    guesses.append("Machine types and software come from the image names and Dockerfiles.")

    entry_names = [m["name"] for m in machines if m["entry"]]
    if entry_names:
        guesses.append(f"Entry points (guess: the service publishes a port): {', '.join(entry_names)}.")
    else:
        guesses.append(
            "No entry point was found, because no service publishes a port. "
            "Set is_entry_point to yes for at least one machine by hand."
        )
    sensitive_names = [m["name"] for m in machines if m["sensitive"]]
    if sensitive_names:
        guesses.append(f"Sensitive machines (guess: databases): {', '.join(sensitive_names)}.")
    else:
        guesses.append("No sensitive machine was found, because there is no database. Set is_sensitive to yes by hand.")

    guesses.extend(found["notes"])

    if not edges:
        guesses.append("No connections could be drawn. Add rows to edges.csv by hand.")
    elif found["guessed"]:
        guesses.append(
            "No links between services were found, so the connections are a guess: entry points to "
            "other machines, then to sensitive machines. Please check edges.csv."
        )
    else:
        guesses.append(
            "Connections come from depends_on, links, and service names used in environment "
            "variables. Please check edges.csv."
        )
    guesses.append("Admin or developer laptops and shared logins cannot be seen in a project. Add them by hand if they matter.")
    guesses.append("No passwords or other values were copied. Only service names, images and ports were used.")

    return {"nodes_csv": nodes_csv, "edges_csv": edges_csv, "guesses": guesses}
