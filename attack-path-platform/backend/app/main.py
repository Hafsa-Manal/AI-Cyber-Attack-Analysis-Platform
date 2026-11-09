"""main.py - the web API (FastAPI). It connects the whole pipeline to the website.

Two endpoints:
  GET  /api/sample    analyze the built-in sample network
  POST /api/analyze   upload nodes.csv and edges.csv (fields "nodes" and "edges")
Add ?live=true to either one to also look up CVEs on NVD (slower, needs internet).
  POST /api/import-nmap   upload an Nmap XML scan (field "scan"), get DRAFT nodes.csv and
                          edges.csv text plus a list of guesses. The user checks the draft,
                          then sends it to /api/analyze.

Both return the "analysis result JSON" (Contract 2 in docs/contracts.md).

The pipeline:
  ingest -> graph_builder -> vuln_matcher -> attacker -> risk -> explain

SAFETY: this is a SIMULATION. The API never scans or connects to any real host.
It only reads the files that are uploaded to it. The only outside call is the optional
NVD lookup (live=true), which is in vuln_matcher.py. Nmap is never run: we only read a scan
file that the user made themselves.
"""
import io
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app.attacker import TechniqueFileError, find_attack_paths
from app.explain import explain_all
from app.graph_builder import GraphBuildError, build_graph, graph_to_dict
from app.ingest import IngestError, load_network
from app.nmap_import import NmapImportError, import_nmap
from app.risk import rank_risks
from app.vuln_matcher import NvdError, VulnDatabaseError, attach_vulnerabilities

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample"
MAX_UPLOAD_BYTES = 1_000_000  # 1 MB per file is plenty for a network description

# The website (Vite) runs on port 5173. Without this, the browser blocks its requests (CORS).
FRONTEND_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

app = FastAPI(title="Attack Path Analysis (simulation only)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def run_analysis(nodes_source, edges_source, live=False):
    """Run the whole pipeline. The inputs can be file paths or open files.
    live=True also asks NVD for CVEs."""
    nodes, edges = load_network(nodes_source, edges_source)  # 1. read and check the CSV files
    graph = build_graph(nodes, edges)  # 2. build the graph
    attach_vulnerabilities(graph, live=live)  # 3. attach CVEs to each machine (live = also ask NVD)
    paths = find_attack_paths(graph)  # 4. find the attack paths
    risks = rank_risks(graph, paths)  # 5. score and rank the machines
    risks, fixes = explain_all(graph, paths, risks)  # 6. explanations and fixes
    return {"graph": graph_to_dict(graph), "paths": paths, "risks": risks, "fixes": fixes}


def analyze_or_fail(nodes_source, edges_source, live=False):
    """Run the pipeline and turn our errors into clear HTTP errors."""
    try:
        return run_analysis(nodes_source, edges_source, live)
    except (IngestError, GraphBuildError) as error:
        # the user's files have a problem: 400 = "bad request"
        raise HTTPException(status_code=400, detail=str(error))
    except NvdError as error:
        # NVD could not be reached or did not answer: 502 = "bad gateway"
        raise HTTPException(status_code=502, detail=str(error))
    except (VulnDatabaseError, TechniqueFileError) as error:
        # our own data files have a problem, not the user's: 500 = "server error"
        raise HTTPException(status_code=500, detail=f"Server data problem: {error}")


async def read_upload(upload, label, missing_message="Please upload both nodes.csv and edges.csv."):
    """Read an uploaded file into memory, with a size limit."""
    if upload is None:
        raise HTTPException(status_code=400, detail=missing_message)
    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"{label} is too big. The limit is 1 MB.")
    return io.BytesIO(data)


@app.get("/api/sample")
def get_sample(live: bool = False):
    """Analyze the built-in sample network."""
    return analyze_or_fail(SAMPLE_DIR / "nodes.csv", SAMPLE_DIR / "edges.csv", live)


@app.post("/api/analyze")
async def analyze(
    nodes: UploadFile | None = File(None),
    edges: UploadFile | None = File(None),
    live: bool = False,
):
    """Analyze the uploaded nodes.csv and edges.csv."""
    nodes_file = await read_upload(nodes, "nodes.csv")
    edges_file = await read_upload(edges, "edges.csv")
    # a live lookup can take a minute, so run it in a separate thread (the server stays responsive)
    return await run_in_threadpool(analyze_or_fail, nodes_file, edges_file, live)


@app.post("/api/import-nmap")
async def import_nmap_scan(scan: UploadFile | None = File(None)):
    """Turn an uploaded Nmap XML scan into DRAFT nodes.csv and edges.csv text, plus our guesses."""
    scan_file = await read_upload(
        scan,
        "scan.xml",
        "Please upload the Nmap scan file (made with: nmap -sV -oX scan.xml <target>).",
    )
    try:
        return import_nmap(scan_file)
    except NmapImportError as error:
        raise HTTPException(status_code=400, detail=str(error))
