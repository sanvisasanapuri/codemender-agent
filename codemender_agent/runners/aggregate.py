# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Stage 3: Aggregator runner for CodeMender Agent."""

from contextlib import closing
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import time
from typing import Optional, Set

from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import PR_MODE_REVIEW_SUGGESTION
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import resolve_pr_remediation_mode
from codemender_agent.storage import download_file_from_gcs
from codemender_agent.storage import get_storage_adapter
from codemender_agent.storage import list_gcs_blobs
from codemender_agent.storage import upload_and_sign_report
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import extract_json_from_output
from codemender_agent.utils import render_token_usage_markdown
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import post_commit_status
from codemender_agent.vcs.github import post_or_update_sticky_comment

logger = logging.getLogger("codemender-orchestrator")


def _get_table_columns(cursor: sqlite3.Cursor, table_name: str, db_prefix: str = "main") -> list[str]:
  """Returns list of column names for a table in specified attached database."""
  try:
    cursor.execute(f"PRAGMA {db_prefix}.table_info({table_name})")
    rows = cursor.fetchall()
    return [r[1] for r in rows]
  except sqlite3.Error:
    return []


def merge_db(base_db_path: str, worker_db_path: str) -> None:
  """Merges worker database tables into base database using selective SQLite UPSERT."""
  if not os.path.exists(worker_db_path):
    logger.warning("Worker database file not found: %s", worker_db_path)
    return

  logger.info("Merging %s into %s...", worker_db_path, base_db_path)
  conn = sqlite3.connect(base_db_path)
  cursor = conn.cursor()
  try:
    # Attach the worker database shard as a named SQLite database
    cursor.execute("ATTACH DATABASE ? AS worker", (worker_db_path,))

    # 1. Findings Table Merge:
    # Match findings by finding_id and update mutable status fields if updated_at is newer
    main_cols = _get_table_columns(cursor, "findings", "main")
    worker_cols = _get_table_columns(cursor, "findings", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "finding_id" in common_cols:
      cols_str = ", ".join(common_cols)
      update_cols = [c for c in common_cols if c != "finding_id"]
      if update_cols:
        set_clause = ", ".join([
            f"{c} = (SELECT {c} FROM worker.findings WHERE finding_id ="
            " main.findings.finding_id)"
            for c in update_cols
        ])
        where_cond = ""
        if "updated_at" in common_cols:
          where_cond = (
              " AND ((SELECT updated_at FROM worker.findings WHERE finding_id ="
              " main.findings.finding_id) >= main.findings.updated_at OR"
              " main.findings.updated_at = '' OR main.findings.updated_at IS"
              " NULL)"
          )
        cursor.execute(f"""
            UPDATE main.findings
            SET {set_clause}
            WHERE finding_id IN (SELECT finding_id FROM worker.findings)
            {where_cond};
        """)

      # Insert any newly recorded findings that do not already exist in the base table
      cursor.execute(f"""
          INSERT OR IGNORE INTO main.findings ({cols_str})
          SELECT {cols_str} FROM worker.findings AS w
          WHERE EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          );
      """)

    # 2. Sessions Table Merge:
    # Merge worker interactive and CLI session tracking rows
    main_cols = _get_table_columns(cursor, "sessions", "main")
    worker_cols = _get_table_columns(cursor, "sessions", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "session_id" in common_cols:
      cols_str = ", ".join(common_cols)
      update_cols = [c for c in common_cols if c != "session_id"]
      if update_cols:
        set_clause = ", ".join([
            f"{c} = (SELECT {c} FROM worker.sessions WHERE session_id ="
            " main.sessions.session_id)"
            for c in update_cols
        ])
        cursor.execute(f"""
            UPDATE main.sessions
            SET {set_clause}
            WHERE session_id IN (SELECT session_id FROM worker.sessions);
        """)

      cursor.execute(f"""
          INSERT OR IGNORE INTO main.sessions ({cols_str})
          SELECT {cols_str} FROM worker.sessions;
      """)

    # 3. Artifacts Table Merge:
    # Exclude auto-incrementing primary key columns ('id', 'artifact_id') to prevent ID collisions
    main_cols = _get_table_columns(cursor, "artifacts", "main")
    worker_cols = _get_table_columns(cursor, "artifacts", "worker")
    common_cols = [c for c in worker_cols if c in main_cols and c not in ["id", "artifact_id"]]

    if common_cols:
      cols_str = ", ".join(common_cols)
      cursor.execute(f"""
          INSERT OR IGNORE INTO main.artifacts ({cols_str})
          SELECT {cols_str} FROM worker.artifacts AS w
          WHERE (w.finding_id IS NULL OR EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          )) AND NOT EXISTS (
              SELECT 1 FROM main.artifacts AS m
              WHERE m.session_id = w.session_id AND m.filename = w.filename
          );
      """)

    # 4. Patches Table Merge:
    # Upsert generated patches and diff metadata associated with remediated findings
    main_cols = _get_table_columns(cursor, "patches", "main")
    worker_cols = _get_table_columns(cursor, "patches", "worker")
    common_cols = [c for c in worker_cols if c in main_cols]

    if common_cols and "patch_id" in common_cols:
      cols_str = ", ".join(common_cols)
      cursor.execute(f"""
          INSERT OR REPLACE INTO main.patches ({cols_str})
          SELECT {cols_str} FROM worker.patches AS w
          WHERE EXISTS (
              SELECT 1 FROM main.findings AS m
              WHERE m.finding_id = w.finding_id
          );
      """)

    # 5. File Hashes Table Merge:
    # Upsert SHA256 hashes of modified repository files to avoid cache invalidations
    cursor.execute("SELECT name FROM main.sqlite_master WHERE type='table' AND name='file_hashes'")
    if cursor.fetchone():
      main_cols = _get_table_columns(cursor, "file_hashes", "main")
      worker_cols = _get_table_columns(cursor, "file_hashes", "worker")
      common_cols = [c for c in worker_cols if c in main_cols]

      if common_cols and "file_path" in common_cols:
        cols_str = ", ".join(common_cols)
        cursor.execute(f"""
            INSERT OR REPLACE INTO main.file_hashes ({cols_str})
            SELECT {cols_str} FROM worker.file_hashes;
        """)

    conn.commit()
    logger.info("Merged %s successfully.", worker_db_path)
  except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
    logger.error("Failed to merge database %s: %s", worker_db_path, e)
    conn.rollback()
  finally:
    # Always detach worker shard database to release locks
    try:
      cursor.execute("DETACH DATABASE worker")
    except sqlite3.Error:  # pylint: disable=broad-exception-caught
      pass
    conn.close()


def _verify_worker_db_counts(
    worker_db_blobs: list[str],
    total_workers_env: Optional[str],
) -> None:
  """Verifies if the number of downloaded DBs matches expected worker count."""
  if not total_workers_env:
    return

  try:
    expected_workers = int(total_workers_env)
    found_indices = set()
    for blob in worker_db_blobs:
      basename = os.path.basename(blob)
      # Parse index from format: worker_[index]_state.db
      parts = basename.split("_")
      if len(parts) >= 2:
        try:
          idx = int(parts[1])
          found_indices.add(idx)
        except ValueError:
          pass

    missing_workers = set(range(expected_workers)) - found_indices
    # Check if any expected worker task indices are absent from downloaded shards
    if missing_workers:
      logger.warning(
          "Missing databases for worker tasks: %s. "
          "The final report might be incomplete.",
          list(missing_workers),
      )
  except ValueError:
    # Log warning if task count string cannot be parsed as an integer
    logger.warning(
        "Invalid CODEMENDER_TOTAL_WORKERS or CLOUD_RUN_TASK_COUNT value: %s",
        total_workers_env,
    )


# -----------------------------------------------------------------------------
# Worker Shard Database Download and Merge Pipeline
# -----------------------------------------------------------------------------
def _download_and_merge_worker_dbs(
    worker_db_blobs: list[str],
    temp_db_dir: str,
    bucket_name: str,
    base_db_path: str,
) -> None:
  """Downloads each worker DB shard from GCS and merges it into base DB."""
  # Iterate over all discovered GCS worker DB blobs and download them locally
  for blob in worker_db_blobs:
    local_worker_db = os.path.join(temp_db_dir, os.path.basename(blob))
    logger.info("Downloading %s...", blob)
    # Merge downloaded worker shard into the base SQLite state database
    if download_file_from_gcs(local_worker_db, bucket_name, blob):
      merge_db(base_db_path, local_worker_db)
    else:
      logger.error("Failed to download worker DB: %s", blob)


def _discover_and_merge_local_worker_dbs(
    workspace_dir: str,
    base_db_path: str,
    storage_adapter: Optional[any] = None,
) -> list[str]:
  """Discovers and merges worker database shards from local/transit directory structure."""
  worker_db_files = []

  # 1. Check .codemender_transit/shards/ recursively for worker SQLite databases
  shards_dir = os.path.join(workspace_dir, ".codemender_transit", "shards")
  if os.path.exists(shards_dir):
    for root, _, files in os.walk(shards_dir):
      for f in sorted(files):
        if f.endswith("_state.db"):
          p = os.path.join(root, f)
          if p not in worker_db_files:
            worker_db_files.append(p)

  # 2. Check worker_dbs directory in workspace
  temp_db_dir = os.path.join(workspace_dir, "worker_dbs")
  if os.path.exists(temp_db_dir):
    for f in sorted(os.listdir(temp_db_dir)):
      if f.endswith("_state.db"):
        p = os.path.join(temp_db_dir, f)
        if p not in worker_db_files:
          worker_db_files.append(p)

  # 3. Check storage adapter listing if no local files were found directly on disk
  if not worker_db_files and storage_adapter:
    blobs = storage_adapter.list_blobs(prefix="shards")
    for blob in blobs:
      if blob.endswith("_state.db"):
        local_path = os.path.join(temp_db_dir, os.path.basename(blob))
        os.makedirs(temp_db_dir, exist_ok=True)
        # Download transit blob to local worker_dbs directory
        if storage_adapter.download_file(local_path, blob):
          if local_path not in worker_db_files:
            worker_db_files.append(local_path)

  logger.info("Discovered %d local worker database shards to merge.", len(worker_db_files))
  # 4. Merge all discovered worker shards into base state.db
  for worker_db in sorted(worker_db_files):
    merge_db(base_db_path, worker_db)

  return worker_db_files


def _aggregate_worker_metadata(
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    worker_db_blobs: list[str],
    storage_adapter: Optional[any] = None,
) -> tuple[dict[str, dict[str, int]], dict[str, str]]:
  """Discovers and parses scan_metadata.json and all worker metadata files to aggregate per-model token usage and finding PR links."""
  token_usage_by_model: dict[str, dict[str, int]] = {}
  finding_prs: dict[str, str] = {}

  def _ingest_token_usage(token_dict: any):
    if not isinstance(token_dict, dict):
      return
    for k, v in token_dict.items():
      if isinstance(v, dict):
        accumulate_model_token_usage(token_usage_by_model, k, v)
      elif isinstance(v, (int, float)):
        accumulate_model_token_usage(token_usage_by_model, "default", token_dict)
        break

  # 1. Ingest Stage 1 scan_metadata.json
  scan_meta_candidates = [
      os.path.join(workspace_dir, "scan_metadata.json"),
      os.path.join(workspace_dir, ".codemender_transit", "base", "scan_metadata.json"),
  ]
  if bucket_name and scan_id and not scan_id.startswith("local"):
    scan_meta_local = os.path.join(workspace_dir, "scan_metadata.json")
    if download_file_from_gcs(scan_meta_local, bucket_name, f"scans/{scan_id}/scan_metadata.json"):
      scan_meta_candidates.append(scan_meta_local)

  for scan_meta_p in list(dict.fromkeys(scan_meta_candidates)):
    if os.path.exists(scan_meta_p):
      try:
        with open(scan_meta_p, "r", encoding="utf-8") as f:
          scan_meta = json.load(f)
        _ingest_token_usage(scan_meta.get("token_usage"))
        break
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse scan_metadata.json: %s", e)

  # 2. Discover Stage 2 worker metadata JSONs
  meta_paths = set()
  # Search .codemender_transit recursively
  transit_dir = os.path.join(workspace_dir, ".codemender_transit")
  if os.path.exists(transit_dir):
    for root, _, files in os.walk(transit_dir):
      for file in files:
        if file.endswith("_metadata.json") and not file.startswith("scan_"):
          meta_paths.add(os.path.join(root, file))

  # Search workspace_dir (e.g. worker_dbs/)
  if os.path.exists(workspace_dir):
    for root, _, files in os.walk(workspace_dir):
      for file in files:
        if file.endswith("_metadata.json") and not file.startswith("scan_"):
          meta_paths.add(os.path.join(root, file))

  # Download from GCS if configured
  if bucket_name and scan_id and not scan_id.startswith("local"):
    try:
      all_blobs = list_gcs_blobs(bucket_name, prefix=f"scans/{scan_id}/worker_")
      meta_blobs = sorted(list(set(
          [b for b in all_blobs if b.endswith("_metadata.json")]
          + [b.replace("_state.db", "_metadata.json") for b in worker_db_blobs]
      )))
      for meta_blob in meta_blobs:
        local_meta = os.path.join(workspace_dir, os.path.basename(meta_blob))
        if download_file_from_gcs(local_meta, bucket_name, meta_blob):
          meta_paths.add(local_meta)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to list/download GCS worker metadata: %s", e)

  for meta_path in sorted(list(meta_paths)):
    if os.path.exists(meta_path):
      try:
        with open(meta_path, "r", encoding="utf-8") as f:
          w_meta = json.load(f)
        _ingest_token_usage(w_meta.get("token_usage"))
        if "finding_prs" in w_meta and isinstance(w_meta["finding_prs"], dict):
          finding_prs.update(w_meta["finding_prs"])
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to parse worker metadata %s: %s", meta_path, e)

  total_in = sum(m.get("in_tokens", 0) for m in token_usage_by_model.values())
  total_out = sum(m.get("out_tokens", 0) for m in token_usage_by_model.values())
  total_all = sum(m.get("total_tokens", 0) for m in token_usage_by_model.values())

  logger.info(
      "\n"
      "======================================================================\n"
      "⚡ AGGREGATED TOKEN USAGE:\n"
      "   Total Input Tokens:  %d\n"
      "   Total Output Tokens: %d\n"
      "   Grand Total Tokens:  %d\n"
      "   Breakdown: %s\n"
      "======================================================================\n",
      total_in,
      total_out,
      total_all,
      json.dumps(token_usage_by_model),
  )
  return token_usage_by_model, finding_prs


def _aggregate_token_metrics(
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    worker_db_blobs: list[str],
    storage_adapter: Optional[any] = None,
) -> dict[str, dict[str, int]]:
  """Wrapper around _aggregate_worker_metadata returning only token totals for backwards compatibility."""
  token_usage, _ = _aggregate_worker_metadata(
      workspace_dir,
      bucket_name,
      scan_id,
      worker_db_blobs,
      storage_adapter=storage_adapter,
  )
  return token_usage


def _inject_token_metrics_into_html(
    html_path: str, token_totals: Optional[dict[str, dict[str, int]]]
) -> None:
  """Injects a Token Usage Summary card/table between the report title and finding count section."""
  if not os.path.exists(html_path) or not token_totals:
    return

  total_in = sum(m.get("in_tokens", 0) for m in token_totals.values())
  total_out = sum(m.get("out_tokens", 0) for m in token_totals.values())
  total_all = sum(m.get("total_tokens", 0) for m in token_totals.values())

  # Build per-model breakdown table if multiple models exist
  breakdown_html = ""
  if len(token_totals) > 1:
    rows = []
    for model_name, metrics in sorted(token_totals.items()):
      m_in = metrics.get("in_tokens", 0)
      m_out = metrics.get("out_tokens", 0)
      m_total = metrics.get("total_tokens", 0)
      rows.append(f"""
        <tr style="border-bottom: 1px solid #e9ecef;">
          <td style="padding: 8px 12px; font-weight: 600; color: #495057;"><code>{model_name}</code></td>
          <td style="padding: 8px 12px; color: #0d6efd;">{m_in:,}</td>
          <td style="padding: 8px 12px; color: #198754;">{m_out:,}</td>
          <td style="padding: 8px 12px; font-weight: 700; color: #212529;">{m_total:,}</td>
        </tr>""")
    rows_str = "".join(rows)
    breakdown_html = f"""
    <div style="margin-top: 18px; border-top: 1px solid #e9ecef; padding-top: 14px;">
      <h4 style="margin-bottom: 8px; font-size: 0.85rem; color: #495057; text-transform: uppercase; letter-spacing: 0.05em;">
        Per-Model Breakdown
      </h4>
      <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem; text-align: left;">
        <thead>
          <tr style="background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;">
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Model</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Input Tokens</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Output Tokens</th>
            <th style="padding: 8px 12px; color: #6c757d; font-weight: 600;">Total Tokens</th>
          </tr>
        </thead>
        <tbody>
          {rows_str}
        </tbody>
      </table>
    </div>"""

  single_model_label = ""
  if len(token_totals) == 1:
    only_model = list(token_totals.keys())[0]
    single_model_label = f' <span style="font-size: 0.8rem; color: #6c757d; font-weight: normal;">(Model: <code>{only_model}</code>)</span>'

  banner_html = f"""
  <div id="codemender-token-metrics-banner" style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <h3 style="margin-bottom: 12px; font-size: 0.95rem; color: #16213e; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 8px;">
      ⚡ LLM Token Usage Summary{single_model_label}
    </h3>
    <div style="display: flex; gap: 40px; flex-wrap: wrap;">
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Input Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #0d6efd;">{total_in:,}</span>
      </div>
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Output Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #198754;">{total_out:,}</span>
      </div>
      <div>
        <span style="font-size: 0.8rem; text-transform: uppercase; color: #6c757d; font-weight: 600; display: block; margin-bottom: 4px;">Total Tokens</span>
        <span style="font-size: 1.5rem; font-weight: 700; color: #212529;">{total_all:,}</span>
      </div>
    </div>
    {breakdown_html}
  </div>
"""
  try:
    with open(html_path, "r", encoding="utf-8") as f:
      content = f.read()

    # 1. Target right before <div class="cards"> (inside main container, above count cards)
    match = re.search(r"(<div\s+class=[\"']cards[\"'][^>]*>)", content, re.IGNORECASE)
    if not match:
      # 2. Fallback: right after </header>
      match = re.search(r"(</header>)", content, re.IGNORECASE)
    if not match:
      # 3. Fallback: right after <h1> title tag
      match = re.search(
          r"(<h1[^>]*>.*?CodeMender Security Report.*?</h1>)",
          content,
          re.IGNORECASE | re.DOTALL,
      )
    if not match:
      # 4. Fallback to <body> tag
      match = re.search(r"(<body[^>]*>)", content, re.IGNORECASE)

    if match:
      # Inject token usage banner into HTML DOM structure
      if match.group(1).lower().startswith("<div"):
        # Insert BEFORE <div class="cards"> container
        pos = match.start()
        new_content = content[:pos] + banner_html + "\n  " + content[pos:]
      else:
        # Insert AFTER opening <body> tag
        pos = match.end()
        new_content = content[:pos] + "\n" + banner_html + content[pos:]
    else:
      new_content = banner_html + "\n" + content

    # Write modified HTML report back to file
    with open(html_path, "w", encoding="utf-8") as f:
      f.write(new_content)
    logger.info("Successfully injected Token Usage Summary into HTML report.")
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to inject token usage into HTML report: %s", e)


def _render_step_summary(
    base_db_path: str,
    config: OrchestratorConfig,
    owner: str,
    repo_name: str,
    target_sha: Optional[str] = None,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
    repo_dir: Optional[str] = None,
    finding_prs: Optional[dict[str, str]] = None,
) -> tuple[str, int]:
  """Renders a comprehensive GitHub Actions Step Summary Markdown dashboard."""
  if not repo_dir and config.workspace_dir and repo_name:
    repo_dir = os.path.join(config.workspace_dir, repo_name)

  severity_badges = {
      "CRITICAL": "🔴 CRITICAL",
      "HIGH": "🟠 HIGH",
      "MEDIUM": "🟡 MEDIUM",
      "LOW": "🔵 LOW",
      "INFO": "⚪ INFO",
  }

  findings_stats = {
      "total": 0,
      "fixed": 0,
      "verified": 0,
      "pre_existing_ignored": 0,
      "skipped_duplicate": 0,
      "dismissed": 0,
      "unfixed": 0,
  }
  findings_list = []

  # 1. Query findings table from SQLite database to calculate status breakdown
  if os.path.exists(base_db_path):
    try:
      with closing(sqlite3.connect(base_db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if cursor.fetchone():
          cols = _get_table_columns(cursor, "findings", "main")
          select_cols = [
              "finding_id",
              "title",
              "status",
              "file_path",
              "start_line",
              "vuln_type",
              "vuln_id",
              "severity",
          ]
          avail_cols = [c for c in select_cols if c in cols]
          cursor.execute(f"SELECT {', '.join(avail_cols)} FROM findings ORDER BY finding_id")
          # 2. Iterate through each finding and bucket into status counters
          for row in cursor.fetchall():
            row_dict = dict(zip(avail_cols, row))
            fid = row_dict.get("finding_id", "")
            status = (row_dict.get("status") or "").upper()

            # In PR scans (Clean as You Code), omit pre-existing ignored, dismissed, and resolved findings
            if config.is_pr_scan and status in (
                "PRE_EXISTING_IGNORED",
                "DISMISSED",
                "FALSE_POSITIVE",
                "RESOLVED",
            ):
              continue

            findings_stats["total"] += 1
            if status in ("FIXED", "REMEDIATED"):
              findings_stats["fixed"] += 1
            elif status in ("VERIFIED", "CONFIRMED"):
              findings_stats["verified"] += 1
            elif status == "PRE_EXISTING_IGNORED":
              findings_stats["pre_existing_ignored"] += 1
            elif status == "SKIPPED_DUPLICATE":
              findings_stats["skipped_duplicate"] += 1
            else:
              # Fold DISMISSED, PR_CREATION_FAILED, and all other unclassified statuses into unfixed
              findings_stats["unfixed"] += 1

            raw_file_path = row_dict.get("file_path", "")
            clean_file_path = normalize_repo_relative_path(
                raw_file_path, repo_dir=repo_dir
            )

            findings_list.append({
                "finding_id": fid,
                "title": row_dict.get("title", ""),
                "status": status or "DETECTED",
                "file_path": clean_file_path,
                "start_line": row_dict.get("start_line", 0),
                "vuln_type": row_dict.get("vuln_type", ""),
                "vuln_id": row_dict.get("vuln_id", ""),
                "severity": (row_dict.get("severity") or "").upper(),
            })
    except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to query base_db for step summary: %s", e)

  # 3. Construct header metadata section (repository, target commit, execution mode)
  mode_labels = {
      "changed_lines": "Pull Request Scan (Clean as You Code)",
      "changed_files": "Pull Request Scan (Clean as You Code - Whole Changed Files)",
      "1hop_impact": "Pull Request Scan (Clean as You Code - 1-Hop Impact: Callers & Callees)",
      "full_repo": "Full Repository Audit (⚠️ Small Repos Only)",
  }
  mode_desc = (
      mode_labels.get(config.pr_scan_mode, "Pull Request Scan (Clean as You Code)")
      if config.is_pr_scan
      else "Nightly Repository Scan"
  )
  commit_desc = target_sha[:8] if target_sha else "HEAD"

  lines = [
      "# 🛡️ CodeMender Security Remediation Summary",
      "",
      f"- **Repository:** `{owner}/{repo_name}`",
      f"- **Target Commit:** `{commit_desc}`",
      f"- **Execution Mode:** `{mode_desc}`",
  ]

  if config.is_pr_scan:
    if findings_stats["total"] > 0:
      # Describe the route the workers actually used to deliver remediations.
      if resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION:
        remediation_hint = (
            "> Remediations have been synthesized and posted as inline review"
            " suggestions. Commit the suggestions on this pull request to"
            " resolve (patches that cannot be suggested inline are delivered as"
            " a Child Pull Request or a patch comment instead)."
        )
      else:
        remediation_hint = (
            "> Remediations have been synthesized. Please review and merge the"
            " proposed Child Pull Request into your feature branch (or apply"
            " the patches) to resolve."
        )
      lines.extend([
          "- **Security Gate:** ❌ **FAILED (Action Required)**",
          "",
          "> [!CAUTION]",
          f"> **Security Gate Status: FAILED ({findings_stats['total']} actionable vulnerability(ies) detected)**",
          "> ",
          remediation_hint,
          "",
      ])
    else:
      lines.extend([
          "- **Security Gate:** ✅ **PASSED (Clean as You Code)**",
          "",
          "> [!NOTE]",
          "> **Security Gate Status: PASSED**",
          "> ",
          "> No new actionable security vulnerabilities detected in the pull request diff.",
          "",
      ])
  else:
    lines.append("")

  lines.extend([
      "### 📊 Remediation Overview",
      "",
      "| Total Discovered | Remediated (Fixed) | Verified (Exploitable) | Pre-Existing Ignored | Skipped Duplicates | Other / Unfixed |",
      "| :---: | :---: | :---: | :---: | :---: | :---: |",
      f"| {findings_stats['total']} | {findings_stats['fixed']} | {findings_stats['verified']} | {findings_stats['pre_existing_ignored']} | {findings_stats['skipped_duplicate']} | {findings_stats['unfixed']} |",
      "",
  ])

  # 4. Construct table of individual findings and remediation outcomes
  if findings_list:
    lines.extend([
        "### 🛠️ Discovered Findings & Remediation Status",
        "",
        "| Finding ID | Severity | Vulnerability Type | Location | Status | Title |",
        "| :--- | :---: | :--- | :--- | :---: | :--- |",
    ])
    for f in findings_list:
      fid = f["finding_id"]
      sev = f.get("severity", "")
      sev_badge = severity_badges.get(sev, f"⚪ {sev}" if sev else "⚪ UNKNOWN")

      vuln_type = (f.get("vuln_type") or "").strip()
      vuln_id = (f.get("vuln_id") or "").strip()
      # Format vulnerability type with CWE ID if present and not already duplicated
      if vuln_id:
        if vuln_type:
          if vuln_id.lower() in vuln_type.lower():
            vuln_display = vuln_type
          else:
            vuln_display = f"{vuln_type} ({vuln_id})"
        else:
          vuln_display = vuln_id
      else:
        vuln_display = vuln_type or "N/A"

      # Location formatting: evaluate file_path:start_line directly (start_line=None/0 evaluates as file:None/0 for whole-file findings by design)
      loc = f"{f['file_path']}:{f['start_line']}" if f["file_path"] else "N/A"
      title_clean = f["title"].replace("|", "\\|") if f["title"] else "-"
      status = f["status"]

      # Format Status with remediation hyperlinking if available
      pr_url = (finding_prs or {}).get(fid)
      if status in ("FIXED", "REMEDIATED") and pr_url:
        # Review and comment anchors live on the scanned pull request itself,
        # so their "/pull/<n>" segment is the parent PR number, not a Child PR.
        if "#discussion_r" in pr_url or "#pullrequestreview-" in pr_url:
          status_display = f"[{status} (suggested)]({pr_url})"
        elif "#issuecomment-" in pr_url:
          status_display = f"[{status} (patch posted)]({pr_url})"
        else:
          pr_match = re.search(r"/pull/(\d+)", pr_url)
          if pr_match:
            status_display = f"[{status} (#{pr_match.group(1)})]({pr_url})"
          else:
            status_display = f"[{status}]({pr_url})"
      else:
        status_display = f"`{status}`"

      lines.append(
          f"| `{fid}` | {sev_badge} | `{vuln_display}` | `{loc}` | {status_display} | {title_clean} |"
      )
    lines.append("")

  # 5. Add callout box pointing to downloadable report artifacts
  lines.extend([
      "> [!TIP]",
      "> 📄 **Interactive Security Report & Export Artifacts**",
      "> Download the **`codemender-report`** archive from the [Artifacts section](#artifacts) below for full interactive HTML graphs, SARIF definitions, and raw JSON telemetry.",
      "",
  ])

  # 6. Construct token usage summary table if metrics are available
  if token_totals:
    token_md = render_token_usage_markdown(token_totals)
    if token_md:
      lines.append(token_md)

  summary_md = "\n".join(lines)

  # 7. Guardrail: 1000 KiB maximum step summary size
  max_bytes = 1000 * 1024
  encoded = summary_md.encode("utf-8")
  if len(encoded) > max_bytes:
    summary_md = encoded[:max_bytes - 200].decode("utf-8", errors="ignore") + "\n\n... *(Summary truncated due to GitHub Step Summary size limit)*\n"

  # 8. Write to GITHUB_STEP_SUMMARY environment file if executing inside GitHub Actions
  summary_file = config.github_step_summary or os.environ.get("GITHUB_STEP_SUMMARY")
  if summary_file:
    try:
      with open(summary_file, "a", encoding="utf-8") as f:
        f.write(summary_md + "\n")
      logger.info("Wrote Step Summary to %s", summary_file)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to write to GITHUB_STEP_SUMMARY (%s): %s", summary_file, e)

  return summary_md, findings_stats["total"]


def _sanitize_sarif_file(
    sarif_path: str,
    repo_dir: str,
    skipped_finding_ids: Optional[Set[str]] = None,
    is_pr_scan: bool = False,
) -> None:
  """Sanitizes SARIF file paths, deduplicates finding messages, and formats Markdown rule help."""
  if not os.path.exists(sarif_path):
    return

  try:
    with open(sarif_path, "r", encoding="utf-8") as f:
      content = f.read()

    data = extract_json_from_output(content)
    if not isinstance(data, dict):
      logger.warning("Failed to extract valid SARIF JSON from %s", sarif_path)
      return

    clean_repo_dir = os.path.abspath(repo_dir)

    # Iterate through all runs and results to normalize file URIs, deduplicate messages, and inject suppressions
    for run in (data.get("runs") or []):
      driver = run.get("tool", {}).get("driver", {})
      rules = driver.get("rules") or []
      rules_by_id = {r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")}

      for result in (run.get("results") or []):
        # 1. Sanitize file URIs to make them workspace-relative (required by GitHub Code Scanning)
        for loc in (result.get("locations") or []):
          phys = loc.get("physicalLocation") or {}
          art = phys.get("artifactLocation") or {}
          uri = art.get("uri", "")
          if uri:
            # Strip file:// URI scheme prefix if present
            if uri.startswith("file://"):
              uri = uri[7:]
            # Normalize absolute paths to repository-relative paths
            if os.path.isabs(uri):
              try:
                rel_path = os.path.relpath(uri, clean_repo_dir).replace("\\", "/")
                # Strip out-of-tree traversal components to prevent GitHub upload-sarif validation errors
                if rel_path.startswith("../") or rel_path == "..":
                  rel_path = re.sub(r"^(\.\./)+", "", rel_path)
                  if not rel_path or rel_path == ".":
                    rel_path = os.path.basename(uri)
                art["uri"] = rel_path
              except ValueError:
                art["uri"] = os.path.basename(uri)
            else:
              clean_uri = uri.replace("\\", "/").lstrip("/")
              if clean_uri.startswith("../") or clean_uri == "..":
                clean_uri = re.sub(r"^(\.\./)+", "", clean_uri)
                if not clean_uri or clean_uri == ".":
                  clean_uri = os.path.basename(uri)
              art["uri"] = clean_uri

        # 2. Locate associated SARIF rule definition by ruleId or ruleIndex
        rule_id = result.get("ruleId")
        rule_idx = result.get("ruleIndex")
        rule_obj = rules_by_id.get(rule_id) if rule_id else None
        if not rule_obj and isinstance(rule_idx, int) and 0 <= rule_idx < len(rules):
          rule_obj = rules[rule_idx]

        # 3. Clean and deduplicate result.message.text and populate rich rule.help.markdown
        msg_obj = result.get("message")
        if isinstance(msg_obj, dict):
          raw_text = msg_obj.get("text", "")
          if raw_text and ": " in raw_text:
            # Split concatenated "Title: Analysis" payload produced by CLI SARIF exporter
            title_part, analysis_part = raw_text.split(": ", 1)
            clean_title = title_part.strip()
            clean_analysis = analysis_part.strip()

            if clean_title:
              # Set clean, concise title on result message bubble above code line
              msg_obj["text"] = clean_title

            if rule_obj and clean_analysis:
              # Promote rich Markdown analysis into rule.help for GitHub Code Scanning UI
              rule_obj["shortDescription"] = {"text": clean_title or rule_obj.get("name", "Vulnerability")}
              rule_obj["help"] = {
                  "text": clean_analysis,
                  "markdown": clean_analysis,
              }
              # Extract first line/sentence for fullDescription summary
              first_line = clean_analysis.split("\n")[0].strip()
              rule_obj["fullDescription"] = {"text": first_line if first_line else clean_title}
          elif rule_obj and not rule_obj.get("help"):
            # Ensure help.markdown is populated from existing fullDescription if help is missing
            full_desc = rule_obj.get("fullDescription", {}).get("text", "")
            if full_desc:
              rule_obj["help"] = {
                  "text": full_desc,
                  "markdown": full_desc,
              }

        # 4. Inject suppression metadata on Nightly scans if finding is SKIPPED_DUPLICATE
        if not is_pr_scan and skipped_finding_ids:
          res_props = result.get("properties") or {}
          finding_id = result.get("ruleId") or res_props.get("finding_id")
          if (finding_id and finding_id in skipped_finding_ids) or res_props.get("status") == "SKIPPED_DUPLICATE":
            # Add SARIF suppression record to avoid duplicate alert notifications on GitHub Code Scanning
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "underReview",
                    "justification": "Remediation PR or branch already exists",
                }
            ]

    # 5. Save sanitized SARIF report back to disk atomically
    with open(sarif_path, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
    logger.info("Successfully sanitized SARIF report: %s", sarif_path)
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log warning if SARIF sanitization fails
    logger.warning("Failed to sanitize SARIF report %s: %s", sarif_path, e)


# -----------------------------------------------------------------------------
# Final Report Generation and Upload Pipeline
# -----------------------------------------------------------------------------
def _generate_and_upload_report(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    codemender_home: str,
    bucket_name: str,
    owner: str,
    repo_name: str,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
    scan_id: Optional[str] = None,
    # Execution mode and filtering configurations
    is_pr_scan: bool = False,
    skipped_finding_ids: Optional[Set[str]] = None,
    storage_mode: str = "gcs",
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Generates final HTML and SARIF reports using cm CLI and uploads to GCS or publishes locally."""
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  logger.info("Generating final consolidated HTML summary report...")

  # 1. Execute 'cm report -f html' to generate full HTML report
  report_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["-f", "html"], cli_version=cli_version
  )
  report_res = run_command(
      report_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=False,
  )

  local_report_path = os.path.join(codemender_home, "reports/report.html")
  if report_res.returncode == 0 or os.path.exists(local_report_path):
    # 2. Inject aggregated LLM token usage metrics into HTML report header
    _inject_token_metrics_into_html(local_report_path, token_totals)

    # 3. Copy HTML report to workspace/repo_dir for artifact capture
    workspace_dir = cfg.workspace_dir or os.getcwd()
    for dest in [
        os.path.join(repo_dir, "report.html"),
        os.path.join(workspace_dir, "report.html"),
    ]:
      if os.path.exists(local_report_path) and os.path.abspath(local_report_path) != os.path.abspath(dest):
        try:
          os.makedirs(os.path.dirname(dest), exist_ok=True)
          shutil.copy2(local_report_path, dest)
        except Exception:  # pylint: disable=broad-exception-caught
          pass

    # Generate JSON report for CI artifact pipelines
    json_cmd = build_cm_command(
        cm_binary, "report", extra_flags=["-f", "json"], cli_version=cli_version
    )
    json_res = run_command(
        json_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=False,
    )
    local_json_path = os.path.join(codemender_home, "reports/report.json")
    if not os.path.exists(local_json_path) and hasattr(json_res, "stdout"):
      json_data = extract_json_from_output(json_res.stdout)
      if json_data is not None:
        try:
          os.makedirs(os.path.dirname(local_json_path), exist_ok=True)
          with open(local_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        except Exception:  # pylint: disable=broad-exception-caught
          pass
    elif os.path.exists(local_json_path):
      try:
        with open(local_json_path, "r", encoding="utf-8") as f:
          raw_json_str = f.read()
        json_data = extract_json_from_output(raw_json_str)
        if json_data is not None:
          with open(local_json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
      except Exception:  # pylint: disable=broad-exception-caught
        pass

    if os.path.exists(local_json_path):
      for dest in [
          os.path.join(repo_dir, "report.json"),
          os.path.join(workspace_dir, "report.json"),
      ]:
        if os.path.abspath(local_json_path) != os.path.abspath(dest):
          try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(local_json_path, dest)
          except Exception:  # pylint: disable=broad-exception-caught
            pass

    # 4. Upload HTML report to GCS bucket and generate signed URL if in GCS mode
    if storage_mode in ["gcs", "local"] and bucket_name:
      report_bucket = cfg.report_bucket or bucket_name
      dest_blob = (
          f"reports/{owner}_{repo_name}/{scan_id}/"
          f"report_{time.strftime('%Y%m%d-%H%M%S')}.html"
          if scan_id
          else f"reports/{owner}_{repo_name}/"
          f"report_{time.strftime('%Y%m%d-%H%M%S')}.html"
      )

      logger.info("Uploading final report to GCS bucket %s...", report_bucket)
      # Upload HTML report to GCS bucket and acquire signed GET URL
      signed_url = upload_and_sign_report(
          local_report_path, report_bucket, dest_blob
      )
      if signed_url:
        # Print high-visibility banner with signed URL for CI logs
        logger.info(
            "\n"
            "======================================================================\n"
            "📊 CONSOLIDATED CODEMENDER SUMMARY REPORT GENERATED:\n"
            "👉 %s\n"
            "======================================================================\n",
            signed_url,
        )
      else:
        # Abort if GCS report upload fails
        logger.critical(
            "Failed to upload or generate signed URL for the consolidated GCS"
            " report."
        )
        sys.exit(1)
  else:
    # Log report generation failure
    logger.error(
        "Failed to execute 'cm report -f html' in aggregator (code %d).",
        report_res.returncode,
    )
    # Abort in GCS mode if report cannot be produced
    if storage_mode == "gcs":
      sys.exit(1)

  # 5. Generate SARIF report for GitHub Security Code Scanning tab
  logger.info("Generating final consolidated SARIF report...")
  sarif_cmd = build_cm_command(
      cm_binary, "report", extra_flags=["-f", "sarif"], cli_version=cli_version
  )
  sarif_res = run_command(
      sarif_cmd,
      cwd=repo_dir,
      env=scrubbed_env,
      check=False,
  )

  # 6. Locate generated SARIF artifact (checking disk paths and stdout fallback)
  sarif_candidates = [
      os.path.join(codemender_home, "reports/report.sarif"),
      os.path.join(repo_dir, "reports/report.sarif"),
      os.path.join(repo_dir, "report.sarif"),
  ]
  found_sarif = None
  for sc in sarif_candidates:
    if os.path.exists(sc):
      found_sarif = sc
      break

  # If cm report printed SARIF to stdout instead of disk, write clean parsed JSON to fallback file
  if not found_sarif and hasattr(sarif_res, "stdout"):
    sarif_data = extract_json_from_output(sarif_res.stdout)
    if sarif_data is not None:
      fallback_sarif = os.path.join(codemender_home, "reports/report.sarif")
      try:
        os.makedirs(os.path.dirname(fallback_sarif), exist_ok=True)
        with open(fallback_sarif, "w", encoding="utf-8") as f:
          json.dump(sarif_data, f, indent=2)
        found_sarif = fallback_sarif
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to write SARIF stdout fallback to disk: %s", e)

  # 7. Sanitize SARIF paths and copy to standard upload locations
  if found_sarif:
    _sanitize_sarif_file(
        found_sarif,
        repo_dir,
        skipped_finding_ids=skipped_finding_ids,
        is_pr_scan=is_pr_scan,
    )
    # Ensure SARIF is placed in repo_dir and workspace root for upload-sarif action
    for target_dest in [
        os.path.join(repo_dir, "report.sarif"),
        os.path.join(workspace_dir, "report.sarif"),
    ]:
      if os.path.abspath(found_sarif) != os.path.abspath(target_dest):
        try:
          os.makedirs(os.path.dirname(target_dest), exist_ok=True)
          shutil.copy2(found_sarif, target_dest)
        except Exception:  # pylint: disable=broad-exception-caught
          pass


def run_aggregate_pipeline() -> None:
  """Executes Stage 3: Download all worker states, merge DBs, generate report, and upload."""
  config = OrchestratorConfig.from_env()
  workspace_dir = config.workspace_dir or os.getcwd()

  # 1. Validate required storage credentials in GCS mode
  if config.storage_mode == "gcs":
    if not config.scan_id or not config.gcs_bucket:
      logger.critical("CODEMENDER_SCAN_ID and CODEMENDER_GCS_BUCKET must be set in GCS mode.")
      sys.exit(1)

  scan_id = config.scan_id or "default"
  bucket_name = config.gcs_bucket or ""

  storage_adapter = get_storage_adapter(
      config.storage_mode,
      bucket_name=config.gcs_bucket,
      base_dir=workspace_dir,
  )

  # 2. Extract repository credentials and paths
  repo_url, token = get_github_credentials(config=config)
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)
  scrubbed_env = get_scrubbed_env()

  # 3. Download or discover scan manifest.json
  manifest_path = os.path.join(workspace_dir, "manifest.json")
  manifest = {}
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Downloading manifest.json from storage...")
    # Fetch manifest.json from GCS or local storage bucket
    if not download_file_from_gcs(
        manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
    ):
      logger.critical("Failed to download manifest.json.")
      sys.exit(1)
  else:
    # In local/GitHub Actions storage mode, locate manifest in workspace or transit base folder
    if not os.path.exists(manifest_path):
      logger.info("Downloading manifest.json from transit storage...")
      if not storage_adapter.download_file(manifest_path, "base/manifest.json"):
        transit_manifest = os.path.join(workspace_dir, ".codemender_transit", "base", "manifest.json")
        if os.path.exists(transit_manifest):
          shutil.copy2(transit_manifest, manifest_path)

  # Parse manifest JSON payload to extract scan target SHA and total findings count
  if os.path.exists(manifest_path):
    try:
      with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to parse manifest.json: %s", e)
  else:
    logger.warning("Manifest not found, continuing with empty manifest.")

  target_sha = manifest.get("target_sha")
  findings_count = manifest.get("findings_count", 0)

  # If zero findings were discovered in Stage 1, emit passing PR Security Gate status and exit
  if findings_count == 0 and "findings_count" in manifest:
    logger.info("Manifest indicates 0 findings. Nothing to aggregate.")
    if config.is_pr_scan:
      target_commit_sha = config.target_sha or target_sha
      if target_commit_sha and token:
        gate_context = "CodeMender / Security Gate"
        gate_desc = (
            "Security Gate PASSED: Clean as You Code (0 active vulnerabilities)."
        )
        logger.info(
            "✅ CodeMender Security Gate PASSED: Clean as You Code. Emitting '%s' commit status check.",
            gate_context,
        )
        post_commit_status(
            token=token,
            owner=owner,
            repo=repo_name,
            sha=target_commit_sha,
            state="success",
            description=gate_desc,
            context=gate_context,
        )
    sys.exit(0)

  # 4. Clone repository to prepare source files for report formatting
  logger.info("Cloning repository for report generation: %s", clean_repo_url)
  if os.path.exists(repo_dir):
    shutil.rmtree(repo_dir)

  # Execute authenticated git clone into repo_dir
  clone_cmd = [
      "git",
      "-c",
      get_git_auth_header(token),
      "clone",
      clean_repo_url,
      repo_dir,
  ]
  run_command(clone_cmd, cwd=workspace_dir)

  # Checkout target commit SHA or resolve default branch
  if target_sha:
    logger.info("Checking out target SHA: %s", target_sha)
    # Fetch explicit target SHA from origin in case of detached or unadvertised PR commits
    fetch_target_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        target_sha,
    ]
    run_command(fetch_target_cmd, cwd=repo_dir, check=False)
    run_command(["git", "checkout", "-f", target_sha], cwd=repo_dir)
  else:
    logger.warning("Target SHA not found in manifest, using default branch.")
    try:
      # Inspect current checked out branch name
      default_branch = run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      default_branch = ""
    # Query remote default branch via GitHub API if local detection is empty
    if not default_branch:
      default_branch = get_default_branch(token, owner, repo_name)
    logger.info("Using default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)

  setup_local_git_excludes(repo_dir)

  # 5. Download & Extract base workspace_base.tar.gz to restore base state.db
  codemender_home = os.path.expanduser("~/.codemender")
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)
  os.makedirs(codemender_home, exist_ok=True)

  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  should_extract = False
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Downloading base workspace...")
    # Download base workspace tarball containing Stage 1 SQLite state.db
    if not download_file_from_gcs(
        tarball_path, bucket_name, f"scans/{scan_id}/workspace_base.tar.gz"
    ):
      logger.critical("Failed to download base workspace.")
      sys.exit(1)
    should_extract = True
  else:
    if os.path.exists(tarball_path):
      should_extract = True
    else:
      logger.info("Downloading base workspace from transit adapter...")
      # Download transit tarball from storage adapter or fallback to local transit base
      if storage_adapter.download_file(tarball_path, "base/workspace_base.tar.gz"):
        should_extract = True
      else:
        transit_tarball = os.path.join(workspace_dir, ".codemender_transit", "base", "workspace_base.tar.gz")
        if os.path.exists(transit_tarball):
          shutil.copy2(transit_tarball, tarball_path)
          should_extract = True

  # Extract tarball contents into ~/.codemender
  if not should_extract:
    logger.critical(
        "Failed to locate or download base workspace tarball in aggregator."
    )
    sys.exit(1)

  logger.info(
      "Extracting base workspace to %s", os.path.dirname(codemender_home)
  )
  try:
    with tarfile.open(tarball_path, "r:gz") as tar:
      # Use safe data_filter on Python 3.12+ to prevent traversal vulnerabilities and deprecation warnings
      if hasattr(tarfile, "data_filter"):
        tar.extractall(path=os.path.dirname(codemender_home), filter="data")
      else:
        tar.extractall(path=os.path.dirname(codemender_home))
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical(
        "Failed to extract base workspace tarball in aggregator: %s", e
    )
    sys.exit(1)

  base_db_path = os.path.join(codemender_home, "state.db")

  # 6. Discover and merge all worker database shards into base_db_path
  worker_db_blobs = []
  if config.storage_mode in ["gcs", "local"]:
    logger.info("Listing worker databases...")
    all_blobs = list_gcs_blobs(bucket_name, f"scans/{scan_id}/")
    worker_db_blobs = [
        b
        for b in all_blobs
        if b.startswith(f"scans/{scan_id}/worker_") and b.endswith("_state.db")
    ]
    logger.info("Found worker DB blobs: %s", worker_db_blobs)

    # Compute expected total workers and verify downloaded shard coverage
    total_workers_str = (
        str(config.total_workers)
        if config.total_workers is not None
        else str(len(manifest.get("partition_urls", [])) or len(manifest.get("upload_urls", [])))
        if (manifest.get("partition_urls") or manifest.get("upload_urls"))
        else None
    )
    _verify_worker_db_counts(worker_db_blobs, total_workers_str)

    temp_db_dir = os.path.join(workspace_dir, "worker_dbs")
    os.makedirs(temp_db_dir, exist_ok=True)
    # Download worker shards from GCS and merge each into base state.db
    _download_and_merge_worker_dbs(worker_db_blobs, temp_db_dir, bucket_name, base_db_path)
  else:
    logger.info("Discovering worker databases in local transit storage...")
    worker_db_blobs = _discover_and_merge_local_worker_dbs(workspace_dir, base_db_path, storage_adapter)
    # Verify local worker shard discovery count
    total_workers_str = (
        str(config.total_workers)
        if config.total_workers is not None
        else str(len(manifest.get("partition_urls", [])) or len(manifest.get("upload_urls", [])))
        if (manifest.get("partition_urls") or manifest.get("upload_urls"))
        else None
    )
    _verify_worker_db_counts(worker_db_blobs, total_workers_str)

  # 7. Aggregate Token Metrics & Worker Metadata
  token_totals = None
  finding_prs: dict[str, str] = {}
  try:
    if config.cli_version == "preview":
      token_totals = _aggregate_token_metrics(
          workspace_dir,
          bucket_name,
          scan_id,
          worker_db_blobs,
      )
    _, finding_prs = _aggregate_worker_metadata(
        workspace_dir,
        bucket_name,
        scan_id,
        worker_db_blobs,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to aggregate worker metadata: %s", e)

  # 8. Render Step Summary before DB cleanup (preserves differential statistics)
  summary_md, active_findings_count = _render_step_summary(
      base_db_path,
      config,
      owner,
      repo_name,
      target_sha=target_sha,
      token_totals=token_totals,
      repo_dir=repo_dir,
      finding_prs=finding_prs,
  )

  # 9. Collect SKIPPED_DUPLICATE IDs for Nightly SARIF suppression
  skipped_finding_ids: Set[str] = set()
  if os.path.exists(base_db_path):
    try:
      with closing(sqlite3.connect(base_db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if cursor.fetchone():
          cursor.execute("SELECT finding_id FROM findings WHERE status = 'SKIPPED_DUPLICATE'")
          skipped_finding_ids = {r[0] for r in cursor.fetchall()}
    except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to collect SKIPPED_DUPLICATE finding IDs: %s", e)

  # 10. Scoped Reporting DB Cleanup (Purge pre-existing ignored findings on PR scans)
  try:
    if os.path.exists(base_db_path):
      with closing(sqlite3.connect(base_db_path)) as conn:
        if config.is_pr_scan:
          # On PR scans, remove pre-existing ignored and duplicates from per-scan report
          conn.execute(
              "DELETE FROM findings WHERE status IN ('PRE_EXISTING_IGNORED', 'SKIPPED_DUPLICATE', 'DISMISSED')"
          )
          logger.info("Purged PRE_EXISTING_IGNORED, SKIPPED_DUPLICATE, and DISMISSED findings for PR report.")
        else:
          # On Nightly scans, retain SKIPPED_DUPLICATE for SARIF suppressions, remove only DISMISSED
          conn.execute("DELETE FROM findings WHERE status IN ('DISMISSED')")
          logger.info("Purged DISMISSED findings for Nightly report.")
        conn.commit()
  except sqlite3.Error as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to perform scoped report findings cleanup in state.db: %s", e)

  # 11. Generate final HTML and SARIF reports and upload
  inject_codemender_config(repo_dir, config=config)
  # Resolve path to CodeMender 'cm' executable
  cm_binary = shutil.which("cm") or "cm"
  log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  # Invoke report generation and upload routine with full run parameters
  _generate_and_upload_report(
      repo_dir,
      scrubbed_env,
      cm_binary,
      codemender_home,
      bucket_name,
      owner,
      repo_name,
      token_totals=token_totals,
      scan_id=scan_id,
      # Pass execution mode and SARIF suppression configurations
      is_pr_scan=config.is_pr_scan,
      skipped_finding_ids=skipped_finding_ids,
      storage_mode=config.storage_mode,
      config=config,
  )

  # 12. Enforce Security Gate for Pull Request Scans via GitHub Commit Status Check
  if config.is_pr_scan:
    target_commit_sha = config.target_sha or target_sha
    if target_commit_sha and token:
      gate_context = "CodeMender / Security Gate"
      if active_findings_count > 0 and config.fail_on_findings:
        gate_state = "failure"
        gate_desc = (
            f"Security Gate FAILED: {active_findings_count} actionable"
            " vulnerability(ies) detected on PR diff."
        )
        logger.warning(
            "❌ CodeMender Security Gate FAILED: %d actionable vulnerability(ies) detected on PR diff. Emitting '%s' commit status check.",
            active_findings_count,
            gate_context,
        )
      else:
        gate_state = "success"
        gate_desc = "Security Gate PASSED: Clean as You Code (0 active vulnerabilities)."
        logger.info(
            "✅ CodeMender Security Gate PASSED: Clean as You Code. Emitting '%s' commit status check.",
            gate_context,
        )

      post_commit_status(
          token=token,
          owner=owner,
          repo=repo_name,
          sha=target_commit_sha,
          state=gate_state,
          description=gate_desc,
          context=gate_context,
      )

  # 13. Mirror the run summary into a single sticky comment on the Pull Request
  # This runs here rather than in the workers because the matrix workers execute
  # in parallel, and a read-modify-write of one shared comment would lose
  # updates. The aggregate stage is single-instance and holds the merged DB.
  if config.is_pr_scan and config.pr_number and token and summary_md:
    # The "#artifacts" anchor only resolves on the workflow run page.
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo_slug = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    run_link = (
        f"[workflow run]({server_url}/{repo_slug}/actions/runs/{run_id})"
        if repo_slug and run_id
        else "the workflow run"
    )
    post_or_update_sticky_comment(
        token=token,
        owner=owner,
        repo=repo_name,
        pr_number=config.pr_number,
        body=summary_md.replace("[Artifacts section](#artifacts) below", run_link),
    )

  # Log final aggregator completion notice
  logger.info("Stage 3 (Aggregate) completed successfully.")
