// UploadPage.jsx - the first screen. The user either:
//   1. picks nodes.csv and edges.csv and clicks "Analyze network", or
//   2. clicks "Load sample network" to try the built-in example.
//
// Props:
//   onResult - function called with the analysis result when it is ready
import { useState } from "react";
import { getSampleResult, analyzeFiles } from "../api.js";

export default function UploadPage({ onResult }) {
  const [nodesFile, setNodesFile] = useState(null); // chosen nodes.csv
  const [edgesFile, setEdgesFile] = useState(null); // chosen edges.csv
  const [loading, setLoading] = useState(false); // true while we wait
  const [error, setError] = useState(""); // message to show if something fails

  // Run a task (sample or analyze) and handle waiting and errors in one place
  async function run(task) {
    setLoading(true);
    setError("");
    try {
      const result = await task();
      onResult(result); // hand the result to App
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function handleAnalyze() {
    // Check the files before sending anything
    if (!nodesFile || !edgesFile) {
      setError("Please choose both nodes.csv and edges.csv.");
      return;
    }
    if (!nodesFile.name.endsWith(".csv") || !edgesFile.name.endsWith(".csv")) {
      setError("Both files must be .csv files.");
      return;
    }
    run(() => analyzeFiles(nodesFile, edgesFile));
  }

  return (
    <main className="upload-page">
      <h1>Attack Path Analysis</h1>
      <p>
        Upload a simulated network. The app finds how an attacker could move through it, ranks the
        weak points, and suggests fixes. This is a simulation only. Nothing is scanned or
        connected to.
      </p>

      <section className="upload-box">
        <label htmlFor="nodes-file">nodes.csv (the machines)</label>
        <input
          id="nodes-file"
          type="file"
          accept=".csv"
          onChange={(e) => setNodesFile(e.target.files[0] || null)}
        />
        <p className="upload-help">
          Columns: id, name, type, software, version, is_entry_point, is_sensitive
        </p>

        <label htmlFor="edges-file">edges.csv (the connections)</label>
        <input
          id="edges-file"
          type="file"
          accept=".csv"
          onChange={(e) => setEdgesFile(e.target.files[0] || null)}
        />
        <p className="upload-help">Columns: source, target, connection, port</p>

        <button onClick={handleAnalyze} disabled={loading}>
          {loading ? "Analyzing..." : "Analyze network"}
        </button>
      </section>

      <p>No files? Try the example network instead.</p>
      <button className="sample-button" onClick={() => run(getSampleResult)} disabled={loading}>
        Load sample network
      </button>

      {/* role="alert" makes screen readers announce the error */}
      {error && (
        <p className="upload-error" role="alert">
          {error}
        </p>
      )}
    </main>
  );
}
