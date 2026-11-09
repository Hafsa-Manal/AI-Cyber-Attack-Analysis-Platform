// api.js - the ONLY file that knows where the data comes from.
// The rest of the app just calls these two functions.
import mockResult from "./mockResult.json";

// true  = use the fake data in mockResult.json (no backend needed)
// false = call the real FastAPI backend
const USE_MOCK = false;

// Where the backend runs (used only when USE_MOCK is false)
const API_URL = "http://localhost:8000";

// live = true also asks the backend to look up CVEs on NVD (slower, needs internet)
function liveQuery(live) {
  return live ? "?live=true" : "";
}

// Get the result for the built-in sample network
export async function getSampleResult(live = false) {
  if (USE_MOCK) return mockResult; // demo mode ignores "live"
  return request(`${API_URL}/api/sample${liveQuery(live)}`);
}

// Send nodes.csv and edges.csv and get the analysis result back
export async function analyzeFiles(nodesFile, edgesFile, live = false) {
  // Demo mode: whatever you upload, we return the same sample result
  if (USE_MOCK) return mockResult;

  const form = new FormData();
  form.append("nodes", nodesFile); // field names must match the backend
  form.append("edges", edgesFile);
  return request(`${API_URL}/api/analyze${liveQuery(live)}`, { method: "POST", body: form });
}

// Send an Nmap scan file (scan.xml). The backend returns a DRAFT:
// { nodes_csv: "...", edges_csv: "...", guesses: ["...", ...] }
export async function importNmap(scanFile) {
  if (USE_MOCK) {
    throw new Error("Nmap import needs the real backend. Set USE_MOCK = false in api.js and start the backend.");
  }
  const form = new FormData();
  form.append("scan", scanFile); // field name must match the backend
  return request(`${API_URL}/api/import-nmap`, { method: "POST", body: form });
}

// Helper: call the backend and turn problems into clear error messages
async function request(url, options) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new Error(`Cannot reach the backend. Is it running at ${API_URL}?`);
  }

  if (!response.ok) {
    let message = `Server error (${response.status})`;
    try {
      // FastAPI sends errors as {"detail": "..."}
      const body = await response.json();
      if (body.detail) {
        message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      // the error had no JSON body, so keep the default message
    }
    throw new Error(message);
  }

  return response.json();
}
