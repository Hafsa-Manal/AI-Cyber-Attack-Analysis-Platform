# Data Contracts

Two JSON shapes connect the two halves of the project.
Both people must follow them exactly.

- **Contract 1 (graph JSON):** Person A produces it, Person B consumes it.
- **Contract 2 (analysis result JSON):** Person B produces it, Person A shows it.

Contract 2 contains Contract 1 inside it (the `graph` field).

---

## Contract 1: graph JSON


{
  "nodes": [
    {
      "id": 1,
      "name": "Public Website",
      "type": "web_server",
      "software": "Apache",
      "version": "2.4.49",
      "is_entry_point": true,
      "is_sensitive": false,
      "vulnerabilities": [
        { "cve": "CVE-2021-41773", "cvss": 7.5, "description": "..." }
      ]
    }
  ],
  "edges": [
    { "source": 1, "target": 3, "connection": "network_access", "port": 445 }
  ]
}


| Field | Meaning |
|---|---|
| `id` | Unique number for the machine |
| `name` | Friendly name shown on the graph |
| `type` | Kind of machine (web_server, workstation, file_server, database, domain_controller) |
| `software`, `version` | Used to look up vulnerabilities |
| `is_entry_point` | `true` = the attacker can start here |
| `is_sensitive` | `true` = the attacker wants to reach this machine |
| `vulnerabilities` | List of known CVEs (empty list if none) |
| `source`, `target` | Edge direction: from machine `source` to machine `target` |
| `connection` | `network_access`, `shared_login` or `db_access` |
| `port` | Port number used by the connection |

---

## Contract 2: analysis result JSON

```json
{
  "graph": { "...": "Contract 1" },
  "paths": [
    {
      "nodes": [1, 3, 4],
      "steps": [
        {
          "from": 1,
          "to": 3,
          "technique_id": "T1210",
          "technique_name": "Exploitation of Remote Services",
          "via": "CVE-xxxx-xxxx"
        }
      ]
    }
  ],
  "risks": [
    { "node": 3, "score": 9.1, "level": "critical", "explanation": "..." }
  ],
  "fixes": [
    { "node": 3, "fix": "..." }
  ]
}
```

| Field | Meaning |
|---|---|
| `paths` | Every attack path found (entry point to sensitive machine) |
| `paths[].nodes` | Machine ids in order along the path |
| `paths[].steps` | One step per hop, labelled with a MITRE ATT&CK technique |
| `steps[].via` | What made the hop possible (a CVE id) |
| `risks` | Weak points, ranked highest score first |
| `risks[].level` | `critical`, `high`, `medium` or `low` |
| `fixes` | One suggested fix per risky machine |

---

## Notes for the demo data (`mockResult.json`)

- For `shared_login` steps there is no CVE, so `via` is `null`.
- The demo risk scores are made up. They only show the shape.
- The CVE descriptions are short and simplified. Check them against NVD
  before the final project.
