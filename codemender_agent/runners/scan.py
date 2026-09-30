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

"""Stage 1: Scan & Dispatch runner for CodeMender Agent."""

import json
import logging
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from typing import Optional
import uuid

# CodeMender CLI JSON parser and version logging
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import parse_findings_json
# Configuration injection and credentials
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
# Storage signed URL and upload utilities
from codemender_agent.storage import generate_signed_url
from codemender_agent.storage import upload_file_to_gcs
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import render_token_usage_markdown
from codemender_agent.utils import resolve_command_model
from codemender_agent.utils import run_command
# Git branch derivation and diff hunk utilities
from codemender_agent.vcs.git import get_finding_branch_name
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import get_pr_changed_lines
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
# GitHub REST API check and deduplication helpers
from codemender_agent.vcs.github import check_remote_branch_exists
from codemender_agent.vcs.github import delete_remote_branch
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import is_duplicate_pr
from codemender_agent.vcs.github import post_commit_status
from codemender_agent.vcs.github import post_or_update_sticky_comment

logger = logging.getLogger("codemender-orchestrator")


EXCLUDED_TAR_PATTERNS = {
    ".git",
    "__pycache__",
    ".venv",
    "node_modules",
    ".pytest_cache",
    ".codemender_cache",
}


def tar_filter(tarinfo: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
  """Filters out heavy/unnecessary metadata directories during workspace archiving."""
  base_name = os.path.basename(tarinfo.name)
  if base_name in EXCLUDED_TAR_PATTERNS or tarinfo.name.endswith(".pyc"):
    return None
  return tarinfo


def make_tarfile(output_filename: str, source_dir: str) -> None:
  """Creates a tar.gz archive of a directory excluding heavy cache/VCS paths."""
  with tarfile.open(output_filename, "w:gz") as tar:
    tar.add(source_dir, arcname=os.path.basename(source_dir), filter=tar_filter)


def _emit_github_output(
    outputs: dict[str, str],
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Emits outputs to GITHUB_OUTPUT environment file if running in GitHub Actions."""
  # 1. Resolve active GITHUB_OUTPUT environment file path
  cfg = config or OrchestratorConfig.from_env()
  output_file = cfg.github_output or os.environ.get("GITHUB_OUTPUT")
  if output_file:
    try:
      # 2. Append key-value pairs to the environment file
      with open(output_file, "a", encoding="utf-8") as f:
        for k, v in outputs.items():
          f.write(f"{k}={v}\n")
      logger.info("Successfully emitted GITHUB_OUTPUT: %s", outputs)
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Log warning if writing to output file fails
      logger.warning("Failed to write to GITHUB_OUTPUT: %s", e)


def _write_clean_sarif_file(
    repo_dir: Optional[str], workspace_dir: str
) -> str:
  """Generates a valid empty SARIF report when zero findings are discovered."""
  clean_sarif = {
      "$schema": (
          "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
      ),
      "version": "2.1.0",
      "runs": [
          {
              "tool": {
                  "driver": {
                      "name": "CodeMender",
                      "semanticVersion": "1.0.0",
                      "rules": [],
                  }
              },
              "results": [],
          }
      ],
  }
  content = json.dumps(clean_sarif, indent=2)
  # Write clean SARIF to both repo_dir and workspace_dir for workflow actions
  for dest_dir in [repo_dir, workspace_dir]:
    if dest_dir and os.path.exists(dest_dir):
      sarif_path = os.path.join(dest_dir, "report.sarif")
      try:
        with open(sarif_path, "w", encoding="utf-8") as f:
          f.write(content)
        logger.info("Wrote clean SARIF report to %s", sarif_path)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Failed to write clean SARIF report to %s: %s", sarif_path, e
        )
  return os.path.join(workspace_dir, "report.sarif")


def _render_zero_findings_summary(
    owner: str,
    repo_name: str,
    target_sha: str,
    is_pr_scan: bool,
    config: Optional[OrchestratorConfig] = None,
    filtered_reasons: Optional[str] = None,
    token_totals: Optional[dict[str, dict[str, int]]] = None,
) -> str:
  """Renders a reassuring Step Summary when zero findings are detected or all are ignored."""
  cfg = config or OrchestratorConfig.from_env()
  summary_file = cfg.github_step_summary or os.environ.get("GITHUB_STEP_SUMMARY")

  mode_desc = (
      "Pull Request Scan (Clean as You Code)"
      if is_pr_scan
      else "Nightly Repository Scan"
  )
  commit_desc = target_sha[:8] if target_sha else "HEAD"
  reason_note = (
      f"\n- **Note:** {filtered_reasons}"
      if filtered_reasons and not is_pr_scan
      else ""
  )
  gate_section = (
      "\n- **Security Gate:** ✅ **PASSED (Clean as You Code)**\n\n"
      "> [!NOTE]\n"
      "> **Security Gate Status: PASSED**\n"
      "> \n"
      "> No new actionable security vulnerabilities detected in the pull request diff."
      if is_pr_scan
      else ""
  )

  token_md = render_token_usage_markdown(token_totals)
  token_section = f"\n{token_md}" if token_md else ""

  summary_md = f"""# 🛡️ CodeMender Security Remediation Summary

- **Repository:** `{owner}/{repo_name}`
- **Target Commit:** `{commit_desc}`
- **Execution Mode:** `{mode_desc}`{reason_note}{gate_section}

### 📊 Remediation Overview

| Total Discovered | Remediated (Fixed) | Verified (Exploitable) | Pre-Existing Ignored | Skipped Duplicates | Other / Unfixed |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 0 | 0 | 0 | 0 | 0 | 0 |

🎉 **No actionable security vulnerabilities detected.**
{token_section}"""
  if summary_file:
    try:
      with open(summary_file, "a", encoding="utf-8") as f:
        f.write(summary_md + "\n")
      logger.info("Wrote Zero-Findings Step Summary to %s", summary_file)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.warning("Failed to write to GITHUB_STEP_SUMMARY (%s): %s", summary_file, e)
  return summary_md


def _finalize_zero_findings_exit(
    owner: str,
    repo_name: str,
    repo_dir: str,
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    target_sha: str,
    token: str,
    config: OrchestratorConfig,
    scan_token_usage: Optional[dict[str, dict[str, int]]] = None,
    filtered_reasons: Optional[str] = None,
) -> None:
  """Finalizes a zero-finding scan with clean SARIF, summary, PR Security Gate status, and GHA outputs."""
  # 1. Generate schema-compliant clean SARIF for GitHub Code Scanning alert resolution
  _write_clean_sarif_file(repo_dir, workspace_dir)
  # 2. Render clean Step Summary before exiting
  summary_md = _render_zero_findings_summary(
      owner,
      repo_name,
      target_sha,
      config.is_pr_scan,
      config=config,
      filtered_reasons=filtered_reasons,
      token_totals=scan_token_usage,
  )
  # 3. Enforce passing Security Gate and update sticky summary on PR scans
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
    if config.pr_number and token and summary_md:
      post_or_update_sticky_comment(
          token=token,
          owner=owner,
          repo=repo_name,
          pr_number=config.pr_number,
          body=summary_md,
      )
  # 4. Build minimal manifest with findings_count = 0
  manifest = {"findings_count": 0, "target_sha": target_sha}
  manifest_path = os.path.join(workspace_dir, "manifest.json")
  with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
  # 5. Upload zero findings manifest to transit storage
  upload_file_to_gcs(
      manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
  )
  # 6. Emit zero findings output variables to GitHub Actions environment
  _emit_github_output(
      {
          "matrix": "[0]",
          "findings_count": "0",
          "target_sha": str(target_sha),
          "scan_id": str(scan_id),
      },
      config=config,
  )
  sys.exit(0)


def _sync_repository(
    repo_url: str,
    token: str,
    repo_dir: str,
    workspace_dir: str,
    target_sha: Optional[str] = None,
    is_pr_scan: bool = False,
    pr_base_ref: Optional[str] = None,
) -> str:
  """Syncs the repository (clones if not exists, fetches and resets if exists).

  Returns:
    The target SHA of the repository after sync.
  """
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)

  logger.info("Syncing repository for scanning: %s", clean_repo_url)

  # 1. Fresh clone if repository directory does not already exist
  if not os.path.exists(os.path.join(repo_dir, ".git")):
    # Clean stale or non-git directory if present to prevent clone destination errors
    if os.path.exists(repo_dir):
      shutil.rmtree(repo_dir)

    # Configure git clone command with authorization header
    clone_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "clone",
    ]
    # In Nightly scans without target SHA use shallow clone depth=1; otherwise preserve full history
    if not is_pr_scan and not target_sha:
      clone_cmd.extend(["--depth", "1"])
    clone_cmd.extend([clean_repo_url, repo_dir])
    run_command(clone_cmd, cwd=workspace_dir)

    # In PR scans, fetch the target PR base reference branch from remote origin
    if is_pr_scan and pr_base_ref:
      fetch_base_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          pr_base_ref,
      ]
      run_command(fetch_base_cmd, cwd=repo_dir, check=False)
  else:
    # 2. Existing workspace: fetch latest branch state and reset working tree
    logger.info("Repository directory exists, fetching latest state...")
    try:
      curr_branch = run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      curr_branch = ""
    if not curr_branch:
      curr_branch = get_default_branch(token, owner, repo_name)

    # Fetch latest commits from remote origin for current branch
    fetch_cmd = [
        "git",
        "-c",
        get_git_auth_header(token),
        "fetch",
        "origin",
        curr_branch,
    ]
    run_command(fetch_cmd, cwd=repo_dir, check=False)

    # In PR scans, ensure PR base reference branch is also fetched
    if is_pr_scan and pr_base_ref:
      fetch_base_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          pr_base_ref,
      ]
      run_command(fetch_base_cmd, cwd=repo_dir, check=False)

    if not is_pr_scan and not target_sha:
      # Force checkout and hard reset to clean up any untracked or modified artifacts
      run_command(["git", "checkout", "-f", curr_branch], cwd=repo_dir, check=False)
      run_command(
          ["git", "reset", "--hard", f"origin/{curr_branch}"], cwd=repo_dir, check=False
      )

  # 3. Checkout specific target commit SHA if requested, or determine default branch
  if target_sha:
    logger.info("Checking out explicit target SHA: %s", target_sha)
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
  elif not is_pr_scan:
    try:
      default_branch = run_command(
          ["git", "branch", "--show-current"], cwd=repo_dir
      ).stdout.strip()
    except Exception:  # pylint: disable=broad-exception-caught
      default_branch = ""
    if not default_branch:
      default_branch = get_default_branch(token, owner, repo_name)

    logger.info("Using default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)

  # 4. Record and return the immutable target Git commit SHA
  target_sha_res = run_command(
      ["git", "rev-parse", "HEAD"], cwd=repo_dir
  ).stdout.strip()
  logger.info("Recorded target Git SHA: %s", target_sha_res)

  # 5. Configure local Git identity and exclusion patterns (.gitignore overrides)
  run_command(["git", "config", "user.name", "CodeMender Agent"], cwd=repo_dir)
  run_command(
      ["git", "config", "user.email", "codemender-agent@google.com"],
      cwd=repo_dir,
  )
  setup_local_git_excludes(repo_dir)

  return target_sha_res


def _init_codemender(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Initializes CodeMender CLI in the repository."""
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  logger.info("Initializing CodeMender CLI...")
  try:
    # 1. Run basic init to create .cm_project metadata
    init_cmd = build_cm_command(cm_binary, "init", cli_version=cli_version)
    run_command(
        init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )

    # 2. Inject repository and environment configs into ~/.codemender/config.yaml
    inject_codemender_config(repo_dir, config=cfg)

    # 3. Verify the initialization (validates build command in container environment)
    verify_init_cmd = build_cm_command(
        cm_binary, "init", extra_flags=["--verify"], cli_version=cli_version
    )
    run_command(
        verify_init_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=True,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical("CodeMender initialization failed: %s", e)
    sys.exit(1)


def _scan_repository(
    repo_dir: str,
    scrubbed_env: dict[str, str],
    cm_binary: str,
    targets: list[str],
    config: Optional[OrchestratorConfig] = None,
) -> tuple[list[dict[str, any]], dict[str, dict[str, int]]]:
  """Runs scan on targets with retries if no findings are found."""
  cfg = config or OrchestratorConfig.from_env()
  cli_version = cfg.cli_version
  max_scan_attempts = 3
  findings = []
  scan_token_usage: dict[str, dict[str, int]] = {}
  find_model = cfg.find_model or resolve_command_model("find") or "default"

  # Retry loop to account for transient cold-start or API rate-limit delays
  for attempt in range(1, max_scan_attempts + 1):
    logger.info("Running scan attempt %d/%d...", attempt, max_scan_attempts)
    # 1. Execute 'cm find' across each configured target directory
    for target in targets:
      try:
        diff_ref = (
            cfg.diff_base_ref
            if (cfg.is_pr_scan and cfg.pr_scan_mode == "1hop_impact")
            else None
        )
        find_cmd = build_cm_command(
            cm_binary, "find", target, cli_version=cli_version, diff_ref=diff_ref
        )
        res = run_command(
            find_cmd,
            cwd=repo_dir,
            env=scrubbed_env,
            check=True,
        )
        # Capture and aggregate token usage telemetry
        token_usage = getattr(res, "token_usage", None)
        if isinstance(token_usage, dict):
          accumulate_model_token_usage(
              scan_token_usage, find_model, token_usage
          )
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Scan failed for target %s: %s", target, e)
        sys.exit(1)

    # 2. Retrieve structured vulnerability findings report in JSON format
    try:
      # Construct 'cm report' command to export discovered findings as JSON
      report_cmd = build_cm_command(
          cm_binary,
          "report",
          extra_flags=["--format", "json"],
          cli_version=cli_version,
      )
      report_res = run_command(
          report_cmd,
          cwd=repo_dir,
          env=scrubbed_env,
          check=True,
          capture_stderr=False,
      )
      # Parse stdout JSON into structured Python dictionary list
      findings = parse_findings_json(report_res.stdout)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error("Failed to get report: %s", e)
      findings = []

    # 3. Exit retry loop early if findings were discovered
    if findings:
      logger.info("Found %d findings on attempt %d.", len(findings), attempt)
      break
    else:
      # Log retry status and delay before next attempt
      logger.warning("No findings found on attempt %d.", attempt)
      if attempt < max_scan_attempts:
        time.sleep(5)

  return findings, scan_token_usage


def _filter_findings(
    findings: list[dict[str, any]],
    repo_url: str,
    token: str,
    repo_dir: str,
    force_overwrite: bool,
    is_pr_scan: bool = False,
    pr_base_ref: Optional[str] = None,
    pr_scan_mode: str = "changed_lines",
) -> tuple[list[dict[str, any]], list[str], list[str]]:
  """Filters findings against PR modified hunks (if PR scan) and remote duplicates."""
  active_findings = []
  skipped_finding_ids = []
  ignored_finding_ids = []
  clean_repo_url = sanitize_git_url(repo_url)

  changed_lines = None
  if is_pr_scan and pr_base_ref and pr_scan_mode not in ("full_repo", "1hop_impact"):
    changed_lines = get_pr_changed_lines(repo_dir, pr_base_ref)
    if changed_lines is None:
      logger.warning(
          "PR Diff Hunk Analysis: git diff failed across all candidate targets for base ref '%s'."
          " Failing-open: retaining all findings without differential hunk suppression.",
          pr_base_ref,
      )
    else:
      logger.info(
          "PR Diff Hunk Analysis: Extracted modified lines across %d files from"
          " origin/%s...HEAD",
          len(changed_lines),
          pr_base_ref,
      )

  for finding in findings:
    finding_id = finding.get("FindingID")
    if not finding_id:
      logger.warning(
          "Finding record missing 'FindingID' (available keys: %s). Skipping."
          " This may indicate an upstream `cm report --format json` schema"
          " change.",
          sorted(finding.keys()),
      )
      continue
    # Only process findings that are not already resolved or false positives
    status = finding.get("Status")
    if status in ["FALSE_POSITIVE", "RESOLVED"]:
      continue

    file_path = normalize_repo_relative_path(
        finding.get("FilePath") or "unknown_file", repo_dir=repo_dir
    )
    try:
      start_line = int(finding.get("StartLine") or 0)
    except ValueError:
      start_line = 0
    try:
      end_line = int(finding.get("EndLine") or start_line)
    except ValueError:
      end_line = start_line

    # 1. PR Scoped Filtering:
    if is_pr_scan and pr_base_ref:
      if pr_scan_mode in ("full_repo", "1hop_impact"):
        pass
      elif pr_scan_mode == "changed_files" and changed_lines is not None:
        if file_path not in changed_lines:
          logger.info("PR Differential Scan (changed_files): Finding %s in %s ignored (file was not touched in PR).", finding_id, file_path)
          ignored_finding_ids.append(finding_id)
          continue
        else:
          logger.info("PR Differential Scan (changed_files): Finding %s in %s matches modified file. Retaining as active.", finding_id, file_path)
      elif pr_scan_mode == "changed_lines" and changed_lines is not None:
        file_changed_lines = changed_lines.get(file_path, set())
        finding_lines = set(range(start_line, max(start_line, end_line) + 1)) if start_line > 0 else {0}
        intersection = file_changed_lines & finding_lines
        if not intersection:
          logger.info("PR Differential Scan: Finding %s in %s (lines %d-%d) is pre-existing legacy debt (not modified in PR). Marking PRE_EXISTING_IGNORED.", finding_id, file_path, start_line, end_line)
          ignored_finding_ids.append(finding_id)
          continue
        else:
          logger.info("PR Differential Scan: Finding %s in %s (lines %d-%d) matches PR modified lines %s. Retaining as active.", finding_id, file_path, start_line, end_line, sorted(intersection))

    # 2. Universal Deduplication: Check if remote branch or PR already exists
    vuln_type = finding.get("VulnType") or "vulnerability"
    branch_name = get_finding_branch_name(file_path, vuln_type, start_line)

    if not force_overwrite and check_remote_branch_exists(
        clean_repo_url, token, branch_name, cwd=repo_dir
    ):
      has_active_pr = is_duplicate_pr(
          clean_repo_url,
          token,
          file_path,
          vuln_type,
          start_line,
          head_branch=branch_name,
      )
      if has_active_pr:
        logger.info(
            "Skipping finding %s as active PR exists for branch %s.",
            finding_id,
            branch_name,
        )
        skipped_finding_ids.append(finding_id)
        continue
      else:
        logger.info(
            "Dead branch detected: %s exists on remote but has no active open PR."
            " Pruning dead branch to allow fresh remediation.",
            branch_name,
        )
        delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)

    elif not force_overwrite and is_duplicate_pr(
        clean_repo_url,
        token,
        file_path,
        vuln_type,
        start_line,
        head_branch=branch_name,
    ):
      logger.info(
          "An open PR covering %s in %s near line %d already exists. Skipping"
          " finding %s.",
          vuln_type,
          file_path,
          start_line,
          finding_id,
      )
      skipped_finding_ids.append(finding_id)
      continue

    # Log active finding retained for Stage 2 remediation
    logger.info(
        "Retaining finding %s (%s in %s near line %d) for remediation.",
        finding_id,
        vuln_type,
        file_path,
        start_line,
    )
    active_findings.append(finding)

  return active_findings, skipped_finding_ids, ignored_finding_ids


def _partition_findings(
    active_findings: list[dict[str, any]],
    max_tasks: int,
) -> list[list[str]]:
  """Partitions active finding IDs into N worker buckets."""
  active_findings_count = len(active_findings)
  effective_max_tasks = max(1, max_tasks)
  num_workers = min(active_findings_count, effective_max_tasks, 10000)
  if num_workers <= 0:
    return []

  logger.info(
      "Partitioning %d active findings into %d workers (max_tasks=%d)",
      active_findings_count,
      num_workers,
      max_tasks,
  )

  # 1. Sort findings by FilePath to group same directory/file findings together
  sorted_findings = sorted(
      active_findings, key=lambda f: f.get("FilePath") or ""
  )
  sorted_ids = [f["FindingID"] for f in sorted_findings]

  # 2. Calculate even partition sizes across available workers
  base_size = active_findings_count // num_workers
  remainder = active_findings_count % num_workers
  sizes = [base_size + (1 if i < remainder else 0) for i in range(num_workers)]

  # 3. Chunk the sorted findings into worker partitions
  partitions = []
  start = 0
  for size in sizes:
    # Append slice to partitions list
    partitions.append(sorted_ids[start : start + size])
    start += size

  return partitions


def _save_and_upload_state(
    partitions: list[list[str]],
    active_findings_count: int,
    target_sha: str,
    workspace_dir: str,
    bucket_name: str,
    scan_id: str,
    scan_token_usage: dict[str, dict[str, int]],
    skipped_duplicate_count: int,
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Saves partitions and manifest, generates signed URLs, and uploads to GCS."""
  # Resolve active configuration instance
  cfg = config or OrchestratorConfig.from_env()

  # 1. Construct scan metadata dictionary with token telemetry and finding counts
  scan_metadata = {
      "scan_id": scan_id,
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "token_usage": scan_token_usage,
      "total_findings_count": active_findings_count + skipped_duplicate_count,
      "active_findings_count": active_findings_count,
      "skipped_duplicate_count": skipped_duplicate_count,
  }
  scan_meta_path = os.path.join(workspace_dir, "scan_metadata.json")
  with open(scan_meta_path, "w", encoding="utf-8") as f:
    json.dump(scan_metadata, f, indent=2)

  # 2. Upload scan_metadata.json to GCS bucket
  if not upload_file_to_gcs(
      scan_meta_path, bucket_name, f"scans/{scan_id}/scan_metadata.json"
  ):
    logger.critical("Failed to upload scan_metadata.json to GCS.")
    sys.exit(1)

  # 3. Archive ~/.codemender state directory containing initialized project metadata
  codemender_home = os.path.expanduser("~/.codemender")
  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  logger.info("Archiving ~/.codemender to %s", tarball_path)
  make_tarfile(tarball_path, codemender_home)

  # 4. Upload workspace_base.tar.gz archive to GCS
  if not upload_file_to_gcs(
      tarball_path, bucket_name, f"scans/{scan_id}/workspace_base.tar.gz"
  ):
    logger.critical("Failed to upload base workspace archive to GCS.")
    sys.exit(1)

  # 5. Generate GET Signed URL for workers to download the base workspace
  base_workspace_blob = f"scans/{scan_id}/workspace_base.tar.gz"
  base_workspace_url = generate_signed_url(
      bucket_name,
      base_workspace_blob,
      expiration_days=cfg.intermediate_retention_days,
      method="GET",
  )

  partition_urls = []
  upload_urls = []
  metadata_urls = []

  # 6. Save each worker partition slice, upload it, and generate signed URLs
  for i, part_ids in enumerate(partitions):
    partition_data = {"partition_index": i, "finding_ids": part_ids}
    part_path = os.path.join(workspace_dir, f"partition_{i}.json")
    with open(part_path, "w", encoding="utf-8") as f:
      json.dump(partition_data, f, indent=2)

    part_blob = f"scans/{scan_id}/partition_{i}.json"
    if not upload_file_to_gcs(part_path, bucket_name, part_blob):
      logger.critical("Failed to upload partition file to GCS.")
      sys.exit(1)

    # Generate Signed URL for workers to download their partition
    part_url = generate_signed_url(
        bucket_name,
        part_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="GET",
    )
    if not part_url:
      logger.critical("Failed to generate GET signed URL for partition %d.", i)
      sys.exit(1)
    partition_urls.append(part_url)

    # Generate Signed URL for workers to upload their mutated DB shard
    worker_db_blob = f"scans/{scan_id}/worker_{i}_state.db"
    upload_url = generate_signed_url(
        bucket_name,
        worker_db_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="PUT",
        content_type="application/octet-stream",
    )
    if not upload_url:
      logger.critical("Failed to generate PUT signed URL for worker %d.", i)
      sys.exit(1)
    upload_urls.append(upload_url)

    # Generate Signed URL for workers to upload their token usage metadata JSON
    worker_meta_blob = f"scans/{scan_id}/worker_{i}_metadata.json"
    meta_put_url = generate_signed_url(
        bucket_name,
        worker_meta_blob,
        expiration_days=cfg.intermediate_retention_days,
        method="PUT",
        content_type="application/json",
    )
    if not meta_put_url:
      logger.critical(
          "Failed to generate PUT signed URL for worker %d metadata.", i
      )
      sys.exit(1)
    metadata_urls.append(meta_put_url)

  # 7. Construct manifest with all Signed URLs and upload to GCS
  manifest = {
      "findings_count": active_findings_count,
      "target_sha": target_sha,
      "base_workspace_url": base_workspace_url,
      "partition_urls": partition_urls,
      "upload_urls": upload_urls,
      "metadata_urls": metadata_urls,
  }
  manifest_path = os.path.join(workspace_dir, "manifest.json")
  with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
  if not upload_file_to_gcs(
      manifest_path, bucket_name, f"scans/{scan_id}/manifest.json"
  ):
    logger.critical("Failed to upload manifest.json to GCS.")
    sys.exit(1)

  # 8. Emit GitHub Actions matrix outputs for dynamic matrix orchestration
  matrix_json = (
      json.dumps(list(range(len(partitions)))) if partitions else "[0]"
  )
  _emit_github_output(
      {
          "matrix": matrix_json,
          "findings_count": str(active_findings_count),
          "target_sha": str(target_sha),
          "scan_id": str(scan_id),
      },
      config=cfg,
  )


def run_scan_pipeline() -> None:
  """Executes Stage 1: Scan repository, filter, partition, and upload state."""
  config = OrchestratorConfig.from_env()
  scan_id = config.scan_id or f"scan_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
  bucket_name = config.gcs_bucket

  # 1. Validate storage configuration when running in GCS mode
  if config.storage_mode == "gcs" and (not config.scan_id or not bucket_name):
    logger.critical(
        "CODEMENDER_SCAN_ID and CODEMENDER_GCS_BUCKET must be set when storage_mode is 'gcs'."
    )
    sys.exit(1)

  if not bucket_name:
    bucket_name = "default_bucket"

  # 2. Extract repository credentials and working directory paths
  repo_url, token = get_github_credentials(config=config)
  workspace_dir = config.workspace_dir or os.getcwd()
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)

  # 3. Synchronize repository and record the target commit SHA
  target_sha = _sync_repository(
      repo_url,
      token,
      repo_dir,
      workspace_dir,
      target_sha=config.target_sha,
      is_pr_scan=config.is_pr_scan,
      pr_base_ref=config.pr_base_ref,
  )

  # 4. Initialize CodeMender CLI environment and local cache paths
  scrubbed_env = get_scrubbed_env(repo_dir=repo_dir)
  cm_binary = shutil.which("cm") or "cm"
  log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
  _init_codemender(repo_dir, scrubbed_env, cm_binary, config=config)

  # 5. Parse scan targets (normalized to absolute paths to prevent sandbox mount errors)
  scan_target_env = config.scan_target
  targets = []
  for part in scan_target_env.split(";"):
    for subpart in part.split(","):
      t = subpart.strip()
      if t:
        abs_t = (
            t if os.path.isabs(t) else os.path.abspath(os.path.join(repo_dir, t))
        )
        targets.append(abs_t)
  if not targets:
    targets = [os.path.abspath(repo_dir)]

  # 6. Execute repository scan and accumulate token usage metrics
  findings, scan_token_usage = _scan_repository(
      repo_dir, scrubbed_env, cm_binary, targets, config=config
  )

  # 7. Handle case where repository scan returns zero findings
  if not findings:
    logger.info("Zero findings confirmed after scanning. Exiting Stage 1.")
    _finalize_zero_findings_exit(
        owner=owner,
        repo_name=repo_name,
        repo_dir=repo_dir,
        workspace_dir=workspace_dir,
        bucket_name=bucket_name,
        scan_id=scan_id,
        target_sha=target_sha,
        token=token,
        config=config,
        scan_token_usage=scan_token_usage,
    )

  # 8. Filter findings against PR differential hunks and deduplicate against open branches/PRs
  force_overwrite = config.force_overwrite
  active_findings, skipped_finding_ids, ignored_finding_ids = _filter_findings(
      findings,
      repo_url,
      token,
      repo_dir,
      force_overwrite,
      is_pr_scan=config.is_pr_scan,
      pr_base_ref=config.pr_base_ref,
      pr_scan_mode=config.pr_scan_mode,
  )

  # 9. Soft-delete skipped & ignored findings in local state.db for telemetry before archiving
  if skipped_finding_ids or ignored_finding_ids:
    db_path = os.path.expanduser("~/.codemender/state.db")
    if os.path.exists(db_path):
      try:
        # Open SQLite connection to record soft-deleted finding statuses
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Mark skipped duplicate findings in SQLite database
        for fid in skipped_finding_ids:
          cursor.execute(
              "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
              " mute_reason = 'Duplicate PR or branch already exists' WHERE"
              " finding_id = ?",
              (fid,),
          )
        # Mark pre-existing ignored findings in SQLite database
        for fid in ignored_finding_ids:
          # Execute soft-delete update query in local findings table
          cursor.execute(
              "UPDATE findings SET status = 'PRE_EXISTING_IGNORED', muted = 1,"
              " mute_reason = 'Pre-existing finding not touched in PR' WHERE"
              " finding_id = ?",
              (fid,),
          )
        conn.commit()
        conn.close()
        logger.info(
            "Dismissed %d skipped and %d ignored findings in local state.db.",
            len(skipped_finding_ids),
            len(ignored_finding_ids),
        )
      except Exception as e:  # pylint: disable=broad-exception-caught
        # Log warning if updating SQLite findings fails
        logger.warning("Failed to update findings in state.db: %s", e)

  # Compute active findings count after filtering
  active_findings_count = len(active_findings)
  logger.info("Active findings after filtering: %d", active_findings_count)

  # Detect total silent finding loss, which indicates upstream schema drift
  if (
      findings
      and active_findings_count == 0
      and not skipped_finding_ids
      and not ignored_finding_ids
  ):
    logger.error(
        "Parsed %d findings but retained 0 active with 0 skipped and 0 ignored."
        " The `cm report --format json` schema is likely unrecognized.",
        len(findings),
    )

  # 10. Handle case where all findings were filtered out
  if active_findings_count == 0:
    logger.info("Zero active findings after filtering. Exiting Stage 1.")
    filtered_reason = (
        None
        if config.is_pr_scan
        else (
            f"{len(ignored_finding_ids)} pre-existing findings and"
            f" {len(skipped_finding_ids)} duplicate branches/PRs dismissed."
        )
    )
    _finalize_zero_findings_exit(
        owner=owner,
        repo_name=repo_name,
        repo_dir=repo_dir,
        workspace_dir=workspace_dir,
        bucket_name=bucket_name,
        scan_id=scan_id,
        target_sha=target_sha,
        token=token,
        config=config,
        scan_token_usage=scan_token_usage,
        filtered_reasons=filtered_reason,
    )

  # 11. Partition findings into balanced worker buckets
  max_tasks = config.max_tasks
  partitions = _partition_findings(active_findings, max_tasks)

  # 12. Save partitioned manifests, archive workspace, generate signed URLs, and upload
  _save_and_upload_state(
      partitions,
      active_findings_count,
      target_sha,
      workspace_dir,
      bucket_name,
      scan_id,
      scan_token_usage,
      len(skipped_finding_ids) + len(ignored_finding_ids),
      config=config,
  )

  logger.info("Stage 1 (Scan) completed successfully.")
