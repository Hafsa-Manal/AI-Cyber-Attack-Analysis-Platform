// ResultsPanel.jsx - shows the attack paths, the ranked risks,
// a plain-English explanation and a fix for each risk.
//
// Props:
//   result            - the full analysis result (Contract 2)
//   selectedPathIndex - which path is chosen (a number), or null for none
//   onSelectPath      - function called with a path number, or null to clear
//   selectedNode      - id of the machine that is selected, or null
//   onSelectNode      - function called with a machine id
export default function ResultsPanel({
  result,
  selectedPathIndex,
  onSelectPath,
  selectedNode,
  onSelectNode,
}) {
  // Make a lookup so we can turn an id (like 3) into a name (like "File Server")
  const names = {};
  result.graph.nodes.forEach((n) => {
    names[n.id] = n.name;
  });

  // Highest score first
  const risks = [...result.risks].sort((a, b) => b.score - a.score);
  const criticalCount = risks.filter((r) => r.level === "critical").length;

  // Find the fix that belongs to one machine
  const fixFor = (nodeId) => result.fixes.find((f) => f.node === nodeId);

  // The path the user picked (or null)
  const chosenPath = selectedPathIndex === null ? null : result.paths[selectedPathIndex];

  return (
    <aside className="results-panel">
      <p className="results-summary">
        {result.paths.length} attack {result.paths.length === 1 ? "path" : "paths"} found,{" "}
        {criticalCount} critical {criticalCount === 1 ? "risk" : "risks"}.
      </p>

      {/* ---------- Attack paths ---------- */}
      <section>
        <h2>Attack paths</h2>

        {result.paths.length === 0 ? (
          <p>No attack path reaches a sensitive machine in this network.</p>
        ) : (
          <>
            <ul className="path-list">
              {result.paths.map((path, index) => (
                <li key={index}>
                  <button
                    className={index === selectedPathIndex ? "path-button selected" : "path-button"}
                    aria-pressed={index === selectedPathIndex}
                    onClick={() => onSelectPath(index)}
                  >
                    {path.nodes.map((id) => names[id]).join(" → ")}
                  </button>
                </li>
              ))}
            </ul>
            <button className="clear-button" onClick={() => onSelectPath(null)}>
              Show whole network
            </button>
          </>
        )}

        {/* Step-by-step view of the chosen path */}
        {chosenPath && (
          <ol className="step-list">
            {chosenPath.steps.map((step, index) => (
              <li key={index}>
                <strong>
                  {names[step.from]} to {names[step.to]}
                </strong>
                <br />
                {step.technique_id} {step.technique_name}
                <br />
                {step.via ? `Uses ${step.via}` : "Uses a shared login (no CVE needed)"}
              </li>
            ))}
          </ol>
        )}
      </section>

      {/* ---------- Ranked risks ---------- */}
      <section>
        <h2> ⚠️ Risk Ranking</h2>
        <ul className="risk-list">
          {risks.map((risk) => {
            const fix = fixFor(risk.node);
            const isSelected = risk.node === selectedNode;
            return (
              <li key={risk.node} className={isSelected ? "risk-card selected" : "risk-card"}>
                <button
                  className="risk-header"
                  aria-pressed={isSelected}
                  onClick={() => onSelectNode && onSelectNode(risk.node)}
                >
                  <span className="risk-name">{names[risk.node]}</span>
                  <span className={`level-badge level-${risk.level}`}>
                    {risk.level} {risk.score.toFixed(1)}
                  </span>
                </button>
                <p className="risk-explanation">{risk.explanation}</p>
                {fix && (
                  <p className="risk-fix">
                    <strong>How to fix:</strong> {fix.fix}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      </section>
    </aside>
  );
}
