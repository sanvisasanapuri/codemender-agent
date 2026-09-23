#!/usr/bin/env python3
import json, os, sqlite3, sys
if "--version" in sys.argv or "version" in sys.argv:
    print("codemender-cli v0.1.0-preview (Vertex AI GKE)")
    sys.exit(0)
os.makedirs(".codemender", exist_ok=True)
conn = sqlite3.connect(".codemender/state.db")
conn.execute("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, status TEXT, severity TEXT, title TEXT, file_path TEXT, line_number INTEGER, data TEXT)")
conn.commit()
conn.close()
print(json.dumps({"session_id": "gke-session-1", "findings": []}))
