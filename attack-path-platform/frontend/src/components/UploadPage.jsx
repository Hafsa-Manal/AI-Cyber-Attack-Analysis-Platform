// UploadPage.jsx - the first screen. The user either:
//   1. picks nodes.csv and edges.csv and clicks "Analyze network", or
//   2. clicks "Load sample network" to try the built-in example, or
//   3. copies a helper prompt, pastes it into an AI chat, and gets both CSV files from it, or
//   4. uploads an Nmap scan file. We turn it into DRAFT files, the user checks them, then analyzes.
//
// Props:
//   onResult - function called with the analysis result when it is ready
import { useState } from "react";
import { getSampleResult, analyzeFiles, importNmap } from "../api.js";

// Look of the two draft text boxes
const TEXTAREA_STYLE = { display: "block", width: "100%", marginTop: "0.4rem", fontFamily: "monospace", fontSize: "0.85rem" };

// Save some text as a file on the user's computer
function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// The prompt people paste into an AI chat. The AI reads their project (repo or zip),
// asks a few questions, and writes the two CSV files.
// The software names in it must match backend/data/vuln_db.json. Update both together.
const HELPER_PROMPT = `You are a friendly helper. I want to describe my project so a security SIMULATOR can analyze it. Help me create two CSV files: nodes.csv and edges.csv. I am a beginner, so use simple words and explain any technical term in one short sentence.

STEP 1: READ MY PROJECT FIRST
Read my connected repo or uploaded zip. Look at: docker-compose.yml, Dockerfile, package.json, requirements.txt, nginx or apache config, deployment files (vercel.json, netlify.toml, firebase.json, Terraform, Kubernetes files, GitHub Actions), the README, database settings, and .env.example (variable names only).
If you cannot open my project, tell me and ask me to upload the zip, or just ask me the questions below.

PRIVACY RULES
- Never read out, copy, or repeat secrets: passwords, API keys, tokens, .env values, or IP addresses.
- Do not paste my code back to me.

STEP 2: SHOW WHAT YOU FOUND
In plain words, list the "machines" or services my project seems to use (for example website hosting, backend/API, database, storage, email, cloud services). For each one give:
- the software and version, and which file told you (or say "guess")
- whether people on the internet can reach it directly (entry point)
- whether losing or leaking it would be a disaster (sensitive, for example the user database)
Do NOT make a machine for each code library. Only things that run as a server or service.

STEP 3: ASK ME ONLY WHAT IS MISSING
Ask 1 or 2 short questions at a time. Wait for my answer. A project's files usually cannot show these, so ask me about them:
- Where it is hosted
- Admin or developer laptops that log in to it
- Shared logins between machines
- Versions you could not find
- Which machine is the most important to protect
If I say "I don't know", help me find out, or leave that value blank.

STEP 4: CONFIRM, THEN CREATE THE FILES
Show a short summary of all machines and connections and ask "Is this correct?" Fix what I correct. Only after I say yes, create the files.

OUTPUT RULES (important)
Give two separate code blocks, labeled nodes.csv and edges.csv, with nothing else inside them.

nodes.csv must have exactly this header:
id,name,type,software,version,is_entry_point,is_sensitive
- id: whole numbers starting at 1, no repeats
- name: short, no commas
- type: one word like web_server, database, workstation, file_server, server
- software and version: leave blank if unknown. Use these exact software names when they fit: Apache, Apache Tomcat, Apache Log4j, Samba, MySQL, PostgreSQL, OpenSSH, PHP, WordPress, MongoDB, Node.js, Microsoft Office, Windows 10, Windows Server. Otherwise use the real product name. For version, give just the version number (like 2.4.49).
- is_entry_point and is_sensitive: only yes or no, in lowercase

edges.csv must have exactly this header:
source,target,connection,port
- source and target: ids from nodes.csv. A row from A to B means "A connects to B" (so an attacker who controls A may reach B).
- connection: only network_access, shared_login, or db_access
- port: a whole number from 1 to 65535. If I don't know it, use the usual one (443 web, 80 http, 22 SSH, 3306 MySQL, 5432 PostgreSQL, 27017 MongoDB, 3389 remote desktop, 445 file sharing).
- Only ONE row for each pair of machines (if both a normal connection and a shared login exist, use shared_login). A machine cannot connect to itself.

At least one machine must be an entry point and at least one must be sensitive.

After the two code blocks:
1. List everything you GUESSED, so I can check it.
2. Tell me in one line how to save the files: paste each into Notepad and save as nodes.csv and edges.csv.

Start now by reading my project.`;

export default function UploadPage({ onResult }) {
  const [nodesFile, setNodesFile] = useState(null); // chosen nodes.csv
  const [edgesFile, setEdgesFile] = useState(null); // chosen edges.csv
  const [loading, setLoading] = useState(false); // true while we wait
  const [error, setError] = useState(""); // message to show if something fails
  const [copyStatus, setCopyStatus] = useState(""); // "", "copied" or "failed"
  const [live, setLive] = useState(false); // also look up CVEs on NVD?
  const [scanFile, setScanFile] = useState(null); // chosen Nmap scan.xml
  const [draft, setDraft] = useState(null); // the draft we made from the scan (or null)
  const [nodesText, setNodesText] = useState(""); // the draft nodes.csv, the user can edit it
  const [edgesText, setEdgesText] = useState(""); // the draft edges.csv, the user can edit it

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
    run(() => analyzeFiles(nodesFile, edgesFile, live));
  }

  // Read the Nmap scan and show the draft
  async function handleReadScan() {
    if (!scanFile) {
      setError("Please choose the Nmap scan file (scan.xml).");
      return;
    }
    if (!scanFile.name.toLowerCase().endsWith(".xml")) {
      setError("The scan must be an .xml file (made with nmap -oX).");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const result = await importNmap(scanFile);
      setDraft(result);
      setNodesText(result.nodes_csv);
      setEdgesText(result.edges_csv);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Analyze the draft files (with the user's changes)
  function handleAnalyzeDraft() {
    const nodes = new File([nodesText], "nodes.csv", { type: "text/csv" });
    const edges = new File([edgesText], "edges.csv", { type: "text/csv" });
    run(() => analyzeFiles(nodes, edges, live));
  }

  // Copy the helper prompt to the clipboard
  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(HELPER_PROMPT);
      setCopyStatus("copied");
    } catch {
      setCopyStatus("failed");
    }
    setTimeout(() => setCopyStatus(""), 3000); // hide the message after 3 seconds
  }

  return (
    <main className="upload-page">
      <h1>Attack Path Analysis</h1>
      <p>
        Upload a simulated network. The app finds how an attacker could move through it, ranks the
        weak points, and suggests fixes. This is a simulation only. Nothing is scanned or
        connected to.
      </p>

      {/* Optional: ask NVD for more CVEs (applies to the buttons below) */}
      <p>
        <label>
          <input
            type="checkbox"
            checked={live}
            disabled={loading}
            onChange={(e) => setLive(e.target.checked)}
          />{" "}
          Also look up live CVEs from NVD (needs internet, can take about a minute)
        </label>
      </p>
      <p className="upload-help">
        Only software names and versions are sent to NVD. It works for common software such as
        Apache, MySQL and Node.js. Other software uses our built-in list only.
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
      <button className="sample-button" onClick={() => run(() => getSampleResult(live))} disabled={loading}>
        Load sample network
      </button>

      {/* Optional: an Nmap scan. We turn it into a draft that the user checks first */}
      <section className="upload-box">
        <h2>Have an Nmap scan?</h2>
        <p className="upload-help">
          Run Nmap yourself, only on a network you own or have permission to scan:{" "}
          <code>nmap -sV -oX scan.xml &lt;your lab network&gt;</code>. Then upload scan.xml here. We only
          read the file. We never run Nmap and never connect to anything.
        </p>
        <label htmlFor="scan-file">scan.xml (the Nmap result)</label>
        <input
          id="scan-file"
          type="file"
          accept=".xml"
          onChange={(e) => setScanFile(e.target.files[0] || null)}
        />
        <button onClick={handleReadScan} disabled={loading}>
          Read scan
        </button>
      </section>

      {draft && (
        <section className="upload-box" aria-labelledby="draft-title">
          <h2 id="draft-title">Draft files: please check them</h2>
          <p className="upload-help">
            A scan cannot show who connects to whom, so these files are guesses. Fix anything that
            is wrong, then analyze.
          </p>
          <div>
            {draft.guesses.map((guess, index) => (
              <p className="upload-help" key={index}>
                {guess}
              </p>
            ))}
          </div>
          <label htmlFor="draft-nodes">nodes.csv</label>
          <textarea
            id="draft-nodes"
            rows={8}
            spellCheck={false}
            value={nodesText}
            onChange={(e) => setNodesText(e.target.value)}
            style={TEXTAREA_STYLE}
          />
          <label htmlFor="draft-edges">edges.csv</label>
          <textarea
            id="draft-edges"
            rows={8}
            spellCheck={false}
            value={edgesText}
            onChange={(e) => setEdgesText(e.target.value)}
            style={TEXTAREA_STYLE}
          />
          <button onClick={handleAnalyzeDraft} disabled={loading} style={{ marginRight: "0.5rem" }}>
            {loading ? "Analyzing..." : "Analyze these files"}
          </button>
          <button onClick={() => downloadText("nodes.csv", nodesText)} style={{ marginRight: "0.5rem" }}>
            Download nodes.csv
          </button>
          <button onClick={() => downloadText("edges.csv", edgesText)}>Download edges.csv</button>
        </section>
      )}

      {loading && live && (
        <p className="upload-help" role="status">
          Asking NVD... this can take a minute.
        </p>
      )}

      {/* role="alert" makes screen readers announce the error */}
      {error && (
        <p className="upload-error" role="alert">
          {error}
        </p>
      )}

      {/* Help for people who do not know what to write in the files */}
      <section className="helper-box">
        <h2>Not sure what to write in the files?</h2>
        <p>Let an AI chat read your project and write both files for you.</p>
        <ol>
          <li>Open an AI chat (Claude, ChatGPT or Gemini) and connect your git repo or upload your project zip.</li>
          <li>Click the button to copy the prompt, paste it into the chat, and answer its few questions.</li>
          <li>Save the two files it gives you as nodes.csv and edges.csv, then upload them above.</li>
        </ol>
        <p>
          The AI will guess some things, so check its list of guesses, especially version numbers.
          Remove .env files from your zip first, and only share your project with an AI chat you trust.
        </p>
        <button onClick={handleCopy}>Copy helper prompt</button>
        {/* role="status" makes screen readers announce the message */}
        <span className="copy-status" role="status">
          {copyStatus === "copied" && "Copied!"}
          {copyStatus === "failed" && "Could not copy. Open \"Show the prompt\" and copy it by hand."}
        </span>
        <details>
          <summary>Show the prompt</summary>
          <pre className="helper-prompt">{HELPER_PROMPT}</pre>
        </details>
      </section>
    </main>
  );
}
