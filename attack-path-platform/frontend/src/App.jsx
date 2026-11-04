// App.jsx - the main screen. It keeps the shared state and decides what to show:
//   no result yet -> the upload page
//   have a result -> the graph on the left and the results panel on the right
import { useState } from "react";
import "./App.css";
import UploadPage from "./components/UploadPage.jsx";
import GraphView from "./components/GraphView.jsx";
import ResultsPanel from "./components/ResultsPanel.jsx";

export default function App() {
  const [result, setResult] = useState(null); // the analysis result (Contract 2)
  const [selectedPathIndex, setSelectedPathIndex] = useState(null); // which attack path is shown
  const [selectedNode, setSelectedNode] = useState(null); // which machine is selected

  // Called by UploadPage when a result is ready
  function handleResult(newResult) {
    setResult(newResult);
    // Start with the first attack path highlighted (if there is one)
    setSelectedPathIndex(newResult.paths.length > 0 ? 0 : null);
    setSelectedNode(null);
  }

  // Go back to the upload page
  function handleReset() {
    setResult(null);
    setSelectedPathIndex(null);
    setSelectedNode(null);
  }

  // No result yet: show the upload page
  if (!result) {
    return <UploadPage onResult={handleResult} />;
  }

  // The path object that GraphView should highlight (or null)
  const chosenPath = selectedPathIndex === null ? null : result.paths[selectedPathIndex];

  return (
    <div className="app">
      <header className="app-header">
        <h1>Attack Path Analysis</h1>
        <p>Simulation only. No real systems are scanned.</p>
        <button onClick={handleReset}>Analyze another network</button>
      </header>

      <div className="app-body">
        <GraphView graph={result.graph} path={chosenPath} onNodeClick={setSelectedNode} />
        <ResultsPanel
          result={result}
          selectedPathIndex={selectedPathIndex}
          onSelectPath={setSelectedPathIndex}
          selectedNode={selectedNode}
          onSelectNode={setSelectedNode}
        />
      </div>
    </div>
  );
}
