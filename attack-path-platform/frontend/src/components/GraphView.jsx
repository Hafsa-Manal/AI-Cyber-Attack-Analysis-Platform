// GraphView.jsx - draws the network as an interactive graph (Cytoscape.js).
//
// Props:
//   graph       - the "graph" part of the result (Contract 1)
//   path        - ONE attack path to highlight (or null for none)
//   onNodeClick - optional function, called with the machine id when clicked
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// Turn our graph JSON into the format Cytoscape understands
function toElements(graph) {
  const nodes = graph.nodes.map((n) => ({
    data: {
      id: String(n.id), // Cytoscape needs ids to be text
      label: `${n.name}\n${n.vulnerabilities.length} CVE`,
      is_entry: n.is_entry_point,
      is_sensitive: n.is_sensitive,
    },
  }));
  const edges = graph.edges.map((e, i) => ({
    data: {
      id: `edge-${i}`,
      source: String(e.source),
      target: String(e.target),
      label: e.connection,
      connection: e.connection,
    },
  }));
  return [...nodes, ...edges];
}

// How things look. Colors tell the role, shapes tell it too (not only color).
const STYLE = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "text-wrap": "wrap",
      "text-valign": "bottom",
      "text-margin-y": 6,
      "font-size": 12,
      width: 38,
      height: 38,
      "background-color": "#8a94a0", // normal machine = grey circle
      "border-width": 2,
      "border-color": "#5f6872",
    },
  },
  {
    // attacker starts here = blue diamond
    selector: "node[?is_entry]",
    style: { shape: "diamond", "background-color": "#2f6fb0", "border-color": "#1d4b7a", width: 46, height: 46 },
  },
  {
    // attacker wants to reach this = red hexagon
    selector: "node[?is_sensitive]",
    style: { shape: "hexagon", "background-color": "#b3261e", "border-color": "#7a1914", width: 46, height: 46 },
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "curve-style": "bezier",
      "line-color": "#a3abb4",
      "target-arrow-color": "#a3abb4",
      "target-arrow-shape": "triangle",
      label: "data(label)",
      "font-size": 10,
      color: "#5f6872",
      "text-background-color": "#ffffff",
      "text-background-opacity": 0.85,
      "text-background-padding": 2,
    },
  },
  // line style also shows the connection type
  { selector: "edge[connection = 'shared_login']", style: { "line-style": "dashed" } },
  { selector: "edge[connection = 'db_access']", style: { "line-style": "dotted" } },

  // Things NOT on the selected attack path fade out
  { selector: ".dimmed", style: { opacity: 0.3 } },
  // Things ON the attack path stand out in orange
  {
    selector: "node.on-path",
    style: { "border-color": "#e07b00", "border-width": 5 },
  },
  {
    selector: "edge.on-path",
    style: { "line-color": "#e07b00", "target-arrow-color": "#e07b00", width: 5, color: "#9a5200" },
  },
];

export default function GraphView({ graph, path, onNodeClick }) {
  const boxRef = useRef(null); // the <div> where the graph is drawn
  const cyRef = useRef(null); // the Cytoscape object

  // Step 1: draw the graph (runs again only if the graph changes)
  useEffect(() => {
    const cy = cytoscape({
      container: boxRef.current,
      elements: toElements(graph),
      style: STYLE,
      layout: {
        name: "breadthfirst", // lays machines out in layers
        directed: true,
        roots: "[?is_entry]", // start the layers from the entry points
        spacingFactor: 1.4,
        padding: 30,
      },
    });

    // tell the parent when a machine is clicked
    cy.on("tap", "node", (event) => {
      if (onNodeClick) onNodeClick(Number(event.target.id()));
    });

    cyRef.current = cy;
    return () => cy.destroy(); // clean up when the graph changes or the page closes
  }, [graph]);

  // Step 2: highlight the chosen attack path (runs when the path changes)
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("on-path dimmed");
    if (!path) return; // no path chosen: show everything normally

    const pathIds = path.nodes.map(String);

    // a link is on the path if it joins two neighbours in the path
    const edgeOnPath = (edge) => {
      for (let i = 0; i < pathIds.length - 1; i++) {
        if (edge.source().id() === pathIds[i] && edge.target().id() === pathIds[i + 1]) return true;
      }
      return false;
    };

    cy.nodes().forEach((node) => {
      node.addClass(pathIds.includes(node.id()) ? "on-path" : "dimmed");
    });
    cy.edges().forEach((edge) => {
      edge.addClass(edgeOnPath(edge) ? "on-path" : "dimmed");
    });
  }, [graph, path]);

  return (
    <div className="graph-view">
      <div ref={boxRef} className="graph-canvas" style={{ width: "100%", height: "100%", minHeight: 420 }} />
      {/* Legend: explains the shapes and line styles */}
      <ul className="graph-legend">
        <li>Blue diamond: attacker starts here</li>
        <li>Red hexagon: sensitive machine</li>
        <li>Grey circle: other machine</li>
        <li>Orange: selected attack path</li>
        <li>Dashed line: shared login. Dotted line: database access.</li>
      </ul>
    </div>
  );
}
