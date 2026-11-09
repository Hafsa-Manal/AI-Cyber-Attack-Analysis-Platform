# Tests for project_import.py. Run them with:  pytest
import io
import zipfile
from pathlib import Path
from textwrap import dedent

import pytest

import app.project_import as pi
from app.attacker import find_attack_paths
from app.graph_builder import build_graph
from app.ingest import load_network
from app.project_import import ProjectImportError, import_project
from app.vuln_matcher import attach_vulnerabilities

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_project.zip"


# ---------- helpers ----------
def make_zip(files):
    """A zip made in memory from {path: text}."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    buffer.seek(0)
    return buffer


def run(files):
    return import_project(make_zip(files))


def compose(text):
    """A project that is just one docker-compose.yml."""
    return run({"docker-compose.yml": dedent(text)})


def table(csv_text):
    rows = [line.split(",") for line in csv_text.strip().split("\n")]
    return [dict(zip(rows[0], row)) for row in rows[1:]]


def edge_rows(draft):
    return [row.split(",") for row in draft["edges_csv"].strip().split("\n")[1:]]


def by_name(draft):
    return {m["name"]: m for m in table(draft["nodes_csv"])}


def text_of(draft):
    return "\n".join(draft["guesses"])


# ---------- the sample project ----------
def test_sample_machines():
    found = table(import_project(SAMPLE)["nodes_csv"])
    assert [m["name"] for m in found] == ["web", "api", "admin", "db"]
    assert [m["type"] for m in found] == ["web_server", "app_server", "web_server", "database"]
    assert [(m["software"], m["version"]) for m in found] == [
        ("Apache", "2.4.49"), ("Node.js", "18"), ("Apache", "2.4.48"), ("MySQL", "5.7.30"),
    ]
    assert [m["is_entry_point"] for m in found] == ["yes", "no", "no", "no"]
    assert [m["is_sensitive"] for m in found] == ["no", "no", "no", "yes"]


def test_sample_connections():
    assert edge_rows(import_project(SAMPLE)) == [
        ["1", "2", "network_access", "3000"],  # web -> api (port from the Dockerfile's EXPOSE)
        ["1", "3", "network_access", "80"],  # web -> admin
        ["2", "4", "db_access", "3306"],  # api -> db
        ["3", "4", "db_access", "3306"],  # admin -> db
    ]


def test_sample_guesses():
    text = text_of(import_project(SAMPLE))
    assert "Read docker-compose.yml: found 4 machines." in text
    assert "Ignored 2 files in folders like node_modules" in text
    assert "Ignored 1 .env file. We never read them" in text
    assert "Entry points (guess: the service publishes a port): web." in text
    assert "Sensitive machines (guess: databases): db." in text
    assert "Connections come from depends_on" in text


def test_ignored_folders_and_code_are_not_used():
    draft = import_project(SAMPLE)
    assert "should-be-ignored" not in draft["nodes_csv"]  # a compose file inside node_modules
    assert "redis" not in draft["nodes_csv"].lower()


def test_secrets_never_appear_anywhere():
    draft = import_project(SAMPLE)
    everything = draft["nodes_csv"] + draft["edges_csv"] + text_of(draft)
    assert "do-not-read-me" not in everything  # the fake .env secrets
    assert "MYSQL_ROOT_PASSWORD" not in everything


def test_the_sample_draft_passes_the_normal_checks_and_gives_a_path():
    draft = import_project(SAMPLE)
    nodes, edges = load_network(io.StringIO(draft["nodes_csv"]), io.StringIO(draft["edges_csv"]))
    graph = attach_vulnerabilities(build_graph(nodes, edges))
    assert [p["nodes"] for p in find_attack_paths(graph)] == [[1, 3, 4]]  # web -> admin -> db


def test_a_path_string_a_path_object_and_an_open_file_all_work():
    first = import_project(str(SAMPLE))
    assert import_project(SAMPLE) == first
    with open(SAMPLE, "rb") as file:
        assert import_project(file) == first
    assert set(first) == {"nodes_csv", "edges_csv", "guesses"}


# ---------- the zip: safety ----------
def test_not_a_zip():
    for content in (b"hello", b""):
        with pytest.raises(ProjectImportError, match="not a valid zip"):
            import_project(io.BytesIO(content))


def test_a_missing_file(tmp_path):
    with pytest.raises(ProjectImportError, match="could not be read"):
        import_project(tmp_path / "nothing.zip")


def test_no_known_files():
    with pytest.raises(ProjectImportError, match="No docker-compose.yml or Dockerfile"):
        run({"README.md": "hi", "src/app.js": "console.log(1)"})


def test_unsafe_paths_are_ignored():
    good = "services:\n  real: {image: nginx}\n"
    evil = "services:\n  evil: {image: nginx}\n"
    unsafe = {
        "../evil/docker-compose.yml": evil,
        "/abs/docker-compose.yml": evil,
        "C:/x/docker-compose.yml": evil,
        "..\\win\\docker-compose.yml": evil,
    }
    with pytest.raises(ProjectImportError, match="No docker-compose.yml"):
        run(unsafe)
    draft = run({**unsafe, "docker-compose.yml": good})
    assert [m["name"] for m in table(draft["nodes_csv"])] == ["real"]


def test_one_outer_folder_and_macos_files_are_handled():
    draft = run({
        "my-project/docker-compose.yml": "services:\n  web: {image: nginx}\n",
        "__MACOSX/my-project/._docker-compose.yml": "junk",
    })
    assert list(by_name(draft)) == ["web"]


def test_files_at_the_top_level_work_too():
    assert list(by_name(run({"docker-compose.yml": "services:\n  web: {image: nginx}\n"}))) == ["web"]


def test_folders_nested_too_deep_are_ignored():
    with pytest.raises(ProjectImportError, match="No docker-compose.yml"):
        run({"a/b/c/d/docker-compose.yml": "services:\n  web: {image: nginx}\n", "q/readme.txt": "x"})


def test_several_compose_files_use_the_one_closest_to_the_top():
    draft = run({
        "docker-compose.yml": "services:\n  top: {image: nginx}\n",
        "deploy/docker-compose.yml": "services:\n  deep: {image: nginx}\n",
    })
    assert list(by_name(draft)) == ["top"]
    assert "Several compose files were found. Only docker-compose.yml was used." in text_of(draft)


def test_env_files_are_never_read_but_env_examples_are_not_counted():
    draft = run({
        "docker-compose.yml": "services:\n  web: {image: nginx}\n",
        ".env": "SECRET=abc",
        "sub/.env.local": "SECRET=abc",
        ".env.example": "SECRET=",
    })
    assert "Ignored 2 .env files" in text_of(draft)


def test_a_file_that_is_too_big_is_skipped_with_a_note():
    big = "services:\n  web: {image: nginx}\n" + "# padding\n" * 30_000  # over 200 KB, but it zips very small
    draft = run({"docker-compose.yml": big, "app/Dockerfile": "FROM node:18\n"})
    assert "Skipped 1 file (too big, over 200 KB)." in text_of(draft)
    assert list(by_name(draft)) == ["app"]  # only the Dockerfile was used


def test_too_many_files_in_the_zip(monkeypatch):
    monkeypatch.setattr(pi, "MAX_ENTRIES", 3)
    with pytest.raises(ProjectImportError, match="more than 3 files"):
        run({f"f{i}.txt": "x" for i in range(4)})


def test_total_size_limit_stops_reading(monkeypatch):
    monkeypatch.setattr(pi, "MAX_TOTAL_BYTES", 300)
    draft = run({
        "docker-compose.yml": "services:\n  web: {image: nginx}\n",
        "app/Dockerfile": "FROM node:18\n" + "# padding\n" * 50,
    })
    assert "some were not read" in text_of(draft)


def test_too_many_files_to_read(monkeypatch):
    monkeypatch.setattr(pi, "MAX_FILES_READ", 1)
    draft = run({"docker-compose.yml": "services:\n  web: {image: nginx}\n", "app/Dockerfile": "FROM node:18\n"})
    assert "some were not read" in text_of(draft)


def test_encrypted_files_are_skipped(monkeypatch):
    original = zipfile.ZipFile.infolist

    def pretend_encrypted(self):
        infos = original(self)
        for info in infos:
            info.flag_bits |= 0x1
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", pretend_encrypted)
    with pytest.raises(ProjectImportError, match="No docker-compose.yml"):
        run({"docker-compose.yml": "services:\n  web: {image: nginx}\n"})


def test_encrypted_files_are_counted_in_the_note(monkeypatch):
    original = zipfile.ZipFile.infolist

    def pretend_one_is_encrypted(self):
        infos = original(self)
        for info in infos:
            if info.filename == "app/Dockerfile":
                info.flag_bits |= 0x1
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", pretend_one_is_encrypted)
    draft = run({"docker-compose.yml": "services:\n  web: {image: nginx}\n", "app/Dockerfile": "FROM node:18\n"})
    assert "Skipped 1 file (encrypted or could not be read)." in text_of(draft)


# ---------- images and versions ----------
def test_image_names_and_tags():
    draft = compose("""
        services:
          s1: {image: "mysql:5.7.30"}
          s2: {image: "postgres:13.2-alpine"}
          s3: {image: "nginx:latest"}
          s4: {image: redis}
          s5: {image: "localhost:5000/mysql:8.0"}
          s6: {image: "mysql:5.7@sha256:abc123"}
          s7: {image: "bitnami/postgresql:14.1"}
          s8: {image: "rabbitmq:3.12"}
          s9: {image: "${IMAGE}"}
          s10: {image: "mysql:${TAG}"}
          s11: {image: "node:18-alpine"}
    """)
    found = by_name(draft)
    got = {name: (m["software"], m["version"], m["type"]) for name, m in found.items()}
    assert got == {
        "s1": ("MySQL", "5.7.30", "database"),
        "s2": ("PostgreSQL", "13.2", "database"),
        "s3": ("nginx", "", "web_server"),
        "s4": ("Redis", "", "database"),
        "s5": ("MySQL", "8.0", "database"),
        "s6": ("MySQL", "5.7", "database"),
        "s7": ("PostgreSQL", "14.1", "database"),
        "s8": ("rabbitmq", "3.12", "server"),
        "s9": ("", "", "server"),
        "s10": ("MySQL", "", "database"),
        "s11": ("Node.js", "18", "app_server"),
    }
    text = text_of(draft)
    assert "s3: the version of nginx is unclear (tag 'latest')" in text
    assert "s4: the version of Redis is unclear (no tag)" in text
    assert "s9: the image name uses a variable" in text
    assert "s10: the version of MySQL is unclear (tag '${TAG}')" in text


def test_a_published_database_port_is_pointed_out():
    draft = compose("""
        services:
          web: {image: nginx, ports: ["80:80"]}
          db: {image: "mysql:5.7.30", ports: ["3306:3306"]}
    """)
    found = by_name(draft)
    assert (found["db"]["is_entry_point"], found["db"]["is_sensitive"]) == ("yes", "yes")
    assert "db: this database publishes port 3306 to the host" in text_of(draft)


def test_all_the_ways_to_write_ports():
    draft = compose("""
        services:
          client:
            image: alpine
            depends_on: [a, b, c, d, e, f, g]
          a: {image: nginx, ports: ["8080:80"]}
          b: {image: nginx, ports: ["127.0.0.1:9090:8081"]}
          c: {image: nginx, ports: ["8443"]}
          d: {image: nginx, ports: [{target: 3000, published: 3001}]}
          e: {image: nginx, ports: ["8000-8010:8000-8010"]}
          f: {image: nginx, expose: ["4000"]}
          g: {image: nginx, ports: ["53:53/udp"]}
    """)
    assert [row[3] for row in edge_rows(draft)] == ["80", "8081", "8443", "3000", "8000", "4000", "53"]
    entry = {name: m["is_entry_point"] for name, m in by_name(draft).items()}
    assert entry == {"client": "no", "a": "yes", "b": "yes", "c": "yes", "d": "yes", "e": "yes", "f": "no", "g": "yes"}


# ---------- connections ----------
def test_links_come_from_depends_on_links_and_environment():
    draft = compose("""
        services:
          web:
            image: nginx
            ports: ["80:80"]
            depends_on:
              api:
                condition: service_started
          api:
            image: "node:18"
            links: ["db:database"]
            environment:
              URL: "https://web.example.com"
          worker:
            image: "node:18"
            environment: ["CACHE=cache-box:6379"]
          db: {image: "mysql:5.7.30"}
          cache: {image: redis, container_name: cache-box}
    """)
    assert edge_rows(draft) == [
        ["1", "2", "network_access", "3000"],  # web -> api (depends_on, dict form)
        ["2", "4", "db_access", "3306"],  # api -> db (links)
        ["3", "5", "db_access", "6379"],  # worker -> cache (a container_name in an environment value)
    ]  # and no edge to "web" from the web.example.com address


def test_environment_styles():
    draft = compose("""
        services:
          app1: {image: "node:18", environment: ["DB_HOST=db"]}
          app2: {image: "node:18", environment: {DATABASE_URL: "postgres://user:pass@db:5432/x"}}
          app3: {image: "node:18", environment: {DATABASE_URL: "postgres://user:pass@notdb:5432/x", NAME: "dbname"}}
          db: {image: "postgres:13.2"}
    """)
    assert edge_rows(draft) == [["1", "4", "db_access", "5432"], ["2", "4", "db_access", "5432"]]


def test_values_are_never_copied():
    draft = compose("""
        services:
          api: {image: "node:18", environment: ["PASSWORD=SuperSecret!123", "DB_HOST=db"]}
          db: {image: "mysql:5.7.30"}
    """)
    assert "SuperSecret" not in draft["nodes_csv"] + draft["edges_csv"] + text_of(draft)


def test_without_any_links_the_connections_are_a_guess():
    draft = compose("""
        services:
          web: {image: nginx, ports: ["80:80"]}
          tool: {image: alpine}
          db: {image: "mysql:5.7.30"}
    """)
    assert edge_rows(draft) == [["1", "2", "network_access", "80"], ["2", "3", "db_access", "3306"]]
    assert "No links between services were found" in text_of(draft)


def test_one_service_has_no_connections():
    draft = compose("services:\n  web: {image: nginx, ports: ['80:80']}\n")
    assert edge_rows(draft) == []
    assert "No connections could be drawn" in text_of(draft)


def test_no_entry_point_and_no_database_are_explained():
    text = text_of(compose("services:\n  a: {image: alpine}\n  b: {image: alpine, depends_on: [a]}\n"))
    assert "No entry point was found" in text
    assert "No sensitive machine was found" in text


# ---------- builds and Dockerfiles ----------
def test_build_uses_the_dockerfile():
    draft = run({
        "docker-compose.yml": "services:\n  client: {image: alpine, depends_on: [api]}\n  api: {build: ./backend}\n",
        "backend/Dockerfile": "FROM node:18-alpine\nEXPOSE 3000\n",
    })
    api = by_name(draft)["api"]
    assert (api["software"], api["version"], api["type"]) == ("Node.js", "18", "app_server")
    assert edge_rows(draft) == [["1", "2", "network_access", "3000"]]


def test_build_with_a_context_and_a_dockerfile_name():
    draft = run({
        "docker-compose.yml": "services:\n  api:\n    build:\n      context: ./svc\n      dockerfile: docker/api.Dockerfile\n",
        "svc/docker/api.Dockerfile": "FROM tomcat:9.0.30\n",
    })
    api = by_name(draft)["api"]
    assert (api["software"], api["version"]) == ("Apache Tomcat", "9.0.30")


def test_build_without_a_dockerfile_in_the_zip():
    draft = run({"docker-compose.yml": "services:\n  api: {build: ./backend}\n  web: {image: nginx}\n"})
    api = by_name(draft)["api"]
    assert (api["software"], api["type"]) == ("", "app_server")
    assert "api: its Dockerfile was not found in the zip" in text_of(draft)


@pytest.mark.parametrize(
    "dockerfile, expected",
    [
        ("FROM node:18 AS build\nRUN npm run build\nFROM nginx:1.25\nCOPY --from=build /a /b\n", ("nginx", "1.25")),
        ("FROM node:18 AS base\nFROM base AS final\n", ("Node.js", "18")),
        ("from node:20\n# FROM nginx:1.0\n", ("Node.js", "20")),
        ("FROM --platform=$BUILDPLATFORM node:18-alpine AS b\n", ("Node.js", "18")),
        ("FROM node:${NODE_VERSION}\n", ("Node.js", "")),
    ],
)
def test_dockerfile_from_lines(dockerfile, expected):
    draft = run({"docker-compose.yml": "services:\n  api: {build: ./b}\n", "b/Dockerfile": dockerfile})
    api = by_name(draft)["api"]
    assert (api["software"], api["version"]) == expected


def test_dockerfile_with_no_usable_from_line():
    draft = run({"docker-compose.yml": "services:\n  api: {build: ./b}\n", "b/Dockerfile": "FROM scratch\n"})
    assert by_name(draft)["api"]["software"] == ""
    assert "api: its Dockerfile has no usable FROM line" in text_of(draft)


def test_expose_uses_the_first_port():
    draft = run({
        "docker-compose.yml": "services:\n  c: {image: alpine, depends_on: [api]}\n  api: {build: ./b}\n",
        "b/Dockerfile": "FROM node:18\nEXPOSE 8080/tcp 9090\n",
    })
    assert edge_rows(draft)[0][3] == "8080"


def test_without_compose_every_dockerfile_is_a_machine():
    draft = run({"app/Dockerfile": "FROM node:18\nEXPOSE 3000\n", "db/Dockerfile": "FROM mysql:5.7\n"})
    found = table(draft["nodes_csv"])
    assert [(m["name"], m["software"], m["version"]) for m in found] == [("app", "Node.js", "18"), ("db", "MySQL", "5.7")]
    assert [m["is_entry_point"] for m in found] == ["yes", "no"]
    assert [m["is_sensitive"] for m in found] == ["no", "yes"]
    assert edge_rows(draft) == [["1", "2", "db_access", "3306"]]
    assert "Read the Dockerfiles: found 2 machines." in text_of(draft)


def test_a_dockerfile_at_the_top_is_called_app():
    draft = run({"Dockerfile": "FROM httpd:2.4.49\nEXPOSE 80\n"})
    assert list(by_name(draft)) == ["app"]
    assert edge_rows(draft) == []


def test_compose_wins_over_dockerfiles():
    draft = run({"docker-compose.yml": "services:\n  web: {image: nginx}\n", "other/Dockerfile": "FROM node:18\n"})
    assert list(by_name(draft)) == ["web"]


# ---------- odd or bad files ----------
def test_odd_value_types_do_not_crash():
    draft = compose("""
        services:
          a:
          b: "text"
          c:
            image: 123
            ports: "80"
            depends_on:
            expose: {x: 1}
    """)
    assert list(by_name(draft)) == ["a", "b", "c"]
    assert by_name(draft)["c"]["is_entry_point"] == "yes"


def test_invalid_yaml_gives_a_message_without_the_file_text():
    with pytest.raises(ProjectImportError, match="docker-compose.yml is not valid YAML") as problem:
        run({"docker-compose.yml": "services: [\n  password: secret-value-123\n"})
    assert "secret-value-123" not in str(problem.value)


@pytest.mark.parametrize("text", ["version: '3'\n", "services: {}\n", "- just\n- a list\n", "services: text\n"])
def test_no_services(text):
    with pytest.raises(ProjectImportError, match="has no services"):
        run({"docker-compose.yml": text})


def test_too_many_services():
    services = "".join(f"  s{i}: {{image: nginx}}\n" for i in range(101))
    with pytest.raises(ProjectImportError, match="The limit is 100"):
        run({"docker-compose.yml": "services:\n" + services})


def test_names_are_safe_and_different():
    draft = compose("""
        services:
          "=evil|calc": {image: "mysql:5.7"}
          "-2+3": {image: nginx}
          web-1: {image: nginx}
          WEB-1: {image: nginx}
    """)
    names = [m["name"] for m in table(draft["nodes_csv"])]
    assert names == ["evil calc", "2 3", "web-1", "WEB-1 2"]
    load_network(io.StringIO(draft["nodes_csv"]), io.StringIO(draft["edges_csv"]))  # still passes the normal checks
