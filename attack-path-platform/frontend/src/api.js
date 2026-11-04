// api.js - the ONLY file that knows where the data comes from.
// The rest of the app just calls these two functions.
import mockResult from "./mockResult.json";

// true  = use the fake data in mockResult.json (no backend needed)
// false = call the real FastAPI backend
const USE_MOCK = true;

// Where the backend runs (used only when USE_MOCK is false)
const API_URL = "http://localhost:8000";

// Get the result for the built-in sample network
export async function getSampleResult() {
  if (USE_MOCK) return mockResult;
  return request(`${API_URL}/api/sample`);
}

// Send nodes.csv and edges.csv and get the analysis result back
export async function analyzeFiles(nodesFile, edgesFile) {
  // Demo mode: whatever you upload, we return the same sample result
  if (USE_MOCK) return mockResult;

  const form = new FormData();
  form.append("nodes", nodesFile); // field names must match the backend
  form.append("edges", edgesFile);
  return request(`${API_URL}/api/analyze`, { method: "POST", body: form });
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
