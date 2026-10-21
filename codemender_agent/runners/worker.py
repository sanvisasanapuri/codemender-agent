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

"""Stage 2: Parallel Worker runner for CodeMender Agent."""

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
from typing import Optional

from codemender_agent.codemender.cli import ensure_cm_binary_version
from codemender_agent.codemender.cli import log_cm_version
from codemender_agent.codemender.cli import validate_model_support
from codemender_agent.codemender.cli import parse_findings_json
from codemender_agent.codemender.db import get_finding_status
from codemender_agent.codemender.db import is_finding_verified
from codemender_agent.config import OrchestratorConfig
from codemender_agent.config import PR_MODE_REVIEW_SUGGESTION
from codemender_agent.config import get_cleanup_ports
from codemender_agent.config import get_github_credentials
from codemender_agent.config import get_scrubbed_env
from codemender_agent.config import inject_codemender_config
from codemender_agent.config import resolve_pr_remediation_mode
from codemender_agent.storage import download_from_url
from codemender_agent.storage import get_storage_adapter
from codemender_agent.storage import upload_to_url
from codemender_agent.utils import accumulate_model_token_usage
from codemender_agent.utils import build_cm_command
from codemender_agent.utils import free_port
from codemender_agent.utils import resolve_command_model
from codemender_agent.utils import run_command
from codemender_agent.vcs.git import clean_workspace
from codemender_agent.vcs.git import filter_stageable_files
from codemender_agent.vcs.git import get_finding_branch_name
from codemender_agent.vcs.git import get_git_auth_header
from codemender_agent.vcs.git import normalize_repo_relative_path
from codemender_agent.vcs.git import parse_patch_to_suggestions
from codemender_agent.vcs.git import parse_repo_owner_and_name
from codemender_agent.vcs.git import push_branch_to_remote
from codemender_agent.vcs.git import sanitize_exploit_and_artifacts
from codemender_agent.vcs.git import sanitize_git_url
from codemender_agent.vcs.git import setup_local_git_excludes
from codemender_agent.vcs.github import MAX_COMMENT_BODY_CHARS
from codemender_agent.vcs.github import build_review_comment
from codemender_agent.vcs.github import check_remote_branch_exists
from codemender_agent.vcs.github import create_pr_comment
from codemender_agent.vcs.github import create_pr_review_with_suggestions
from codemender_agent.vcs.github import create_pull_request
from codemender_agent.vcs.github import delete_remote_branch
from codemender_agent.vcs.github import finding_marker
from codemender_agent.vcs.github import format_suggestion_body
from codemender_agent.vcs.github import get_default_branch
from codemender_agent.vcs.github import get_pr_diff_line_ranges
from codemender_agent.vcs.github import is_duplicate_pr
from codemender_agent.vcs.github import list_reviewed_finding_ids

logger = logging.getLogger("codemender-orchestrator")


def _setup_git_and_checkout(
    clean_repo_url: str,
    token: str,
    repo_dir: str,
    workspace_dir: str,
    target_sha: Optional[str],
    owner: str,
    repo_name: str,
    is_pr_scan: bool = False,
) -> tuple[str, str]:
  """Clones the repository and checkouts the working base ref (target SHA for PRs, default branch for Nightly).

  Returns:
    Tuple of (default_branch, working_base_ref).
  """
  logger.info("Cloning repository: %s", clean_repo_url)

  # 1. Clean workspace directory if previously populated
  if os.path.exists(repo_dir):
    shutil.rmtree(repo_dir)

  # 2. Clone repository from GitHub using authentication header
  clone_cmd = [
      "git",
      "-c",
      get_git_auth_header(token),
      "clone",
      clean_repo_url,
      repo_dir,
  ]
  run_command(clone_cmd, cwd=workspace_dir)

  # 3. Determine the repository's default branch (e.g. main/master)
  try:
    default_branch = run_command(
        ["git", "branch", "--show-current"], cwd=repo_dir
    ).stdout.strip()
  except Exception:  # pylint: disable=broad-exception-caught
    default_branch = ""
  if not default_branch:
    default_branch = get_default_branch(token, owner, repo_name)

  # 4. Checkout the target commit SHA (for PRs) or default branch (for Nightly)
  working_base_ref = target_sha if (is_pr_scan and target_sha) else (target_sha or default_branch)
  if working_base_ref:
    logger.info("Checking out working base ref: %s", working_base_ref)
    if target_sha:
      # Fetch explicit target SHA from origin to support detached or unadvertised PR commits
      fetch_target_cmd = [
          "git",
          "-c",
          get_git_auth_header(token),
          "fetch",
          "origin",
          target_sha,
      ]
      run_command(fetch_target_cmd, cwd=repo_dir, check=False)
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
  else:
    logger.info("Using default branch: %s", default_branch)
    run_command(["git", "checkout", "-f", default_branch], cwd=repo_dir)
    working_base_ref = default_branch

  # 5. Configure local Git identity and exclusion patterns
  run_command(["git", "config", "user.name", "CodeMender Agent"], cwd=repo_dir)
  run_command(
      ["git", "config", "user.email", "codemender-agent@google.com"],
      cwd=repo_dir,
  )
  setup_local_git_excludes(repo_dir)

  return default_branch, working_base_ref


def _restore_state(
    base_workspace_url: str,
    partition_url: str,
    workspace_dir: str,
    worker_index: int,
    codemender_home: str,
) -> tuple[str, list[str]]:
  """Downloads and extracts base workspace tarball and worker partition file."""
  # 1. Reset local ~/.codemender directory
  if os.path.exists(codemender_home):
    shutil.rmtree(codemender_home)
  os.makedirs(codemender_home, exist_ok=True)

  # 2. Download base workspace tarball (contains initialized SQLite state.db)
  tarball_path = os.path.join(workspace_dir, "workspace_base.tar.gz")
  if not os.path.exists(tarball_path):
    logger.info("Downloading base workspace from URL: %s", base_workspace_url)
    if not download_from_url(base_workspace_url, tarball_path):
      # Fallback to local transit directory if running in local/GitHub Actions mode
      transit_tarball = os.path.join(workspace_dir, ".codemender_transit", "base", "workspace_base.tar.gz")
      if os.path.exists(transit_tarball):
        shutil.copy2(transit_tarball, tarball_path)
      else:
        logger.critical("Failed to download base workspace.")
        sys.exit(1)

  # 3. Extract base workspace archive into user home directory
  logger.info(
      "Extracting base workspace to %s", os.path.dirname(codemender_home)
  )
  if os.path.exists(tarball_path):
    try:
      with tarfile.open(tarball_path, "r:gz") as tar:
        # Use safe data_filter on Python 3.12+ to prevent traversal vulnerabilities and deprecation warnings
        if hasattr(tarfile, "data_filter"):
          tar.extractall(path=os.path.dirname(codemender_home), filter="data")
        else:
          tar.extractall(path=os.path.dirname(codemender_home))
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.critical("Failed to extract base workspace tarball: %s", e)
      sys.exit(1)

  # 4. Download assigned worker partition JSON file
  partition_path = os.path.join(workspace_dir, f"partition_{worker_index}.json")
  if not os.path.exists(partition_path):
    logger.info("Downloading partition from URL: %s", partition_url)
    if not download_from_url(partition_url, partition_path):
      transit_part = os.path.join(workspace_dir, ".codemender_transit", "base", f"partition_{worker_index}.json")
      if os.path.exists(transit_part):
        shutil.copy2(transit_part, partition_path)
      else:
        logger.critical("Failed to download partition.")
        sys.exit(1)

  # 5. Parse partition slice to extract assigned Finding IDs
  with open(partition_path, "r", encoding="utf-8") as f:
    partition_data = json.load(f)
  # Extract list of finding IDs assigned to this worker shard
  finding_ids = partition_data.get("finding_ids", [])
  logger.info("Worker assigned findings: %s", finding_ids)

  # Return partition metadata tuple
  return partition_path, finding_ids


def _mark_skipped_duplicate(
    state_db_path: str, finding_id: str, reason: str
) -> None:
  """Mutes a finding in the worker state database as an already-handled duplicate."""
  if not os.path.exists(state_db_path):
    return
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      conn.execute(
          "UPDATE findings SET status = 'SKIPPED_DUPLICATE', muted = 1,"
          " mute_reason = ? WHERE finding_id = ?",
          (reason, finding_id),
      )
      conn.commit()
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Failed to set SKIPPED_DUPLICATE in worker state.db: %s", e)


def _skip_if_duplicate_branch_or_pr(
    clean_repo_url: str,
    token: str,
    repo_dir: str,
    branch_name: str,
    file_path: str,
    vuln_type: str,
    start_line: int,
    finding_id: str,
    state_db_path: str,
) -> bool:
  """Reports whether a branch or PR already remediates this finding."""
  is_branch_dup = check_remote_branch_exists(
      clean_repo_url, token, branch_name, cwd=repo_dir
  )
  is_pr_dup = is_duplicate_pr(
      clean_repo_url,
      token,
      file_path,
      vuln_type,
      start_line,
      head_branch=branch_name,
  )
  if not (is_branch_dup or is_pr_dup):
    return False

  logger.info(
      "Finding %s skipped due to existing duplicate branch/PR.", finding_id
  )
  _mark_skipped_duplicate(
      state_db_path, finding_id, "Duplicate PR or branch already exists"
  )
  return True


# -----------------------------------------------------------------------------
# Fork Pull Request Patch Comment Construction
# -----------------------------------------------------------------------------
def _fit_fork_comment(
    header: str, diff_section: str, apply_section: str, footer: str
) -> str:
  """Assembles the fork patch comment, dropping sections that will not fit.

  The patch appears twice (once to read, once inside a `git apply` heredoc), so
  a large diff overflows GitHub's comment limit. Sections are dropped whole
  rather than letting the body be cut mid-patch: a truncated heredoc still
  renders as a complete-looking block, and pasting it yields a corrupt patch.
  """
  oversize_note = (
      "> [!WARNING]\n"
      "> The patch is too large to embed in a pull request comment. Download"
      " the `codemender-report` artifact from the workflow run for the full"
      " diff.\n\n"
  )
  candidates = (
      header + diff_section + apply_section + footer,
      header + diff_section + footer,
      header + oversize_note + footer,
  )
  for body in candidates:
    if len(body) <= MAX_COMMENT_BODY_CHARS:
      return body
  # Even the header alone is oversized; the API layer truncates as a last resort.
  return candidates[-1]


# -----------------------------------------------------------------------------
# GitHub Review Suggestion Construction
# -----------------------------------------------------------------------------
def _build_suggestion_comments(
    finding_id: str,
    finding_meta: dict[str, any],
    repo_dir: str,
    patch_diff: str,
    pr_diff_line_ranges: dict[str, set[int]],
) -> tuple[list[dict], Optional[str]]:
  """Converts a fix patch into inline suggestion comments, or reports a blocker.

  Remediation is offered as a suggestion only when the *entire* patch can be
  expressed as one-click suggestions. A patch that creates, renames or deletes
  files, or that touches a line GitHub will not render as part of the PR diff,
  is rejected wholesale so the caller can route it to a fallback instead of
  posting a partial fix the reviewer could mistake for a complete one.

  Returns:
    Tuple of (comments, blocker_reason). Exactly one is populated.
  """
  # 1. Translate the unified diff into anchorable replacement hunks
  hunks, blockers = parse_patch_to_suggestions(repo_dir, patch_diff)
  if blockers:
    return [], "; ".join(blockers)
  if not hunks:
    return [], "the fix produced no suggestable hunks"

  # 2. Reject the whole patch unless every anchor line is inside the PR diff
  for hunk in hunks:
    addressable = pr_diff_line_ranges.get(hunk.path)
    if not addressable:
      return [], f"`{hunk.path}` is not part of the reviewable pull request diff"
    outside = [
        line
        for line in range(hunk.start_line, hunk.end_line + 1)
        if line not in addressable
    ]
    if outside:
      return [], (
          f"`{hunk.path}` line(s) {outside[0]}-{outside[-1]} fall outside the"
          " pull request diff"
      )

  # 3. Render one suggestion comment per hunk, each carrying the dedup marker
  marker = finding_marker(finding_id)
  severity = finding_meta.get("severity") or "UNKNOWN"
  vuln_type = finding_meta.get("vuln_type") or "vulnerability"
  analysis = finding_meta.get("analysis") or ""
  total = len(hunks)

  comments: list[dict] = []
  for index, hunk in enumerate(hunks, start=1):
    if index == 1:
      preamble = (
          f"{marker}\n"
          f"### 🛡️ CodeMender: {severity} `{vuln_type}`\n\n"
          f"{analysis}\n\n"
          f"Commit the suggestion below to apply the fix"
          f"{f' (part 1 of {total})' if total > 1 else ''}."
      )
    else:
      preamble = (
          f"{marker}\n"
          f"🛡️ **CodeMender** — part {index} of {total} of the fix for"
          f" `{vuln_type}` in this pull request."
      )
    comments.append(
        build_review_comment(
            path=hunk.path,
            start_line=hunk.start_line,
            end_line=hunk.end_line,
            body=format_suggestion_body(hunk.replacement_lines, preamble=preamble),
        )
    )

  return comments, None


# -----------------------------------------------------------------------------
# Single Finding Remediation and PR Pipeline
# -----------------------------------------------------------------------------
def _process_finding(
    finding_id: str,
    finding: dict[str, any],
    repo_dir: str,
    cm_binary: str,
    scrubbed_env: dict[str, str],
    clean_repo_url: str,
    # Authentication credentials and repository metadata
    token: str,
    owner: str,
    repo_name: str,
    default_branch: str,
    working_base_ref: str,
    state_db_path: str,
    worker_token_usage: dict[str, dict[str, int]],
    config: OrchestratorConfig,
    pr_diff_line_ranges: Optional[dict[str, set[int]]] = None,
    already_suggested: Optional[set[str]] = None,
) -> Optional[str]:
  """Handles verification, surgical staging, and PR routing for a single finding.

  Returns:
    The URL of the remediation that was delivered — an inline suggestion
    review, a fork patch comment, or a Child Pull Request — or None when the
    finding was skipped or no remediation could be routed.
  """
  # 1. Extract finding metadata, vulnerability type, and target file path
  cli_version = config.cli_version
  vuln_type = finding.get("VulnType") or "vulnerability"
  file_path = normalize_repo_relative_path(
      finding.get("FilePath") or "unknown_file", repo_dir=repo_dir
  )
  # Extract title, severity, and analysis details from finding record
  title = finding.get("Title") or f"Security Fix for {vuln_type}"
  severity = finding.get("Severity") or "UNKNOWN"
  analysis = finding.get("Analysis") or "Automated fix generated by CodeMender."
  # Resolve model overrides for verification and fix stages
  verify_model = config.verify_model or resolve_command_model("verify") or "default"
  fix_model = config.fix_model or resolve_command_model("fix") or "default"

  try:
    start_line = int(finding.get("StartLine") or 0)
  except ValueError:
    start_line = 0

  # 2. Compute canonical branch name for finding
  branch_name = get_finding_branch_name(file_path, vuln_type, start_line)

  # 3. Resolve the remediation route for this finding
  suggestion_mode = (
      config.is_pr_scan
      and bool(config.pr_number)
      and resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION
  )

  logger.info(
      "Processing finding %s (Branch: %s, Remediation: %s)",
      finding_id,
      branch_name,
      "review suggestion" if suggestion_mode else "pull request",
  )

  # 1. Enforce force_overwrite = False on all PR scans to avoid branch clobbering
  force_overwrite = config.force_overwrite and not config.is_pr_scan

  if suggestion_mode:
    # No branch or PR is created in suggestion mode, so remote-branch dedup
    # cannot apply. The marker embedded in a previously posted suggestion is
    # the equivalent idempotency signal across re-runs.
    if already_suggested and finding_id in already_suggested:
      logger.info(
          "Finding %s skipped; a suggestion was already posted on PR #%s.",
          finding_id,
          config.pr_number,
      )
      _mark_skipped_duplicate(
          state_db_path, finding_id, "Suggestion already posted on this PR"
      )
      return
  elif not force_overwrite:
    if _skip_if_duplicate_branch_or_pr(
        clean_repo_url,
        token,
        repo_dir,
        branch_name,
        file_path,
        vuln_type,
        start_line,
        finding_id,
        state_db_path,
    ):
      return

  # 2. Verification Retry Loop (Executes 'cm verify' with port cleanup)
  if not config.skip_verify:
    max_verify_attempts = 3
    verified = False

    for attempt in range(1, max_verify_attempts + 1):
      logger.info(
          "Verifying finding %s (Attempt %d/%d)...",
          finding_id,
          attempt,
          max_verify_attempts,
      )
      # Free configured development ports before running probers/exploit verification
      for port in get_cleanup_ports(config=config):
        free_port(port)

      # Reset repository workspace to clean state before running verify
      run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
      clean_workspace(repo_dir)

      # Execute 'cm verify' command
      verify_cmd = build_cm_command(
          cm_binary, "verify", finding_id, cli_version=cli_version
      )
      verify_res = run_command(
          verify_cmd,
          cwd=repo_dir,
          env=scrubbed_env,
          check=False,
      )
      token_usage = getattr(verify_res, "token_usage", None)
      if isinstance(token_usage, dict):
        accumulate_model_token_usage(
            worker_token_usage, verify_model, token_usage
        )

      # Free cleanup ports after verification completes
      for port in get_cleanup_ports(config=config):
        free_port(port)

      # Check whether the verification succeeded and state.db reflects verification
      if verify_res.returncode == 0 and is_finding_verified(
          state_db_path, finding_id
      ):
        logger.info("Successfully verified finding %s.", finding_id)
        verified = True
        break
      else:
        logger.warning(
            "Attempt %d failed to verify finding %s.", attempt, finding_id
        )
        if attempt < max_verify_attempts:
          time.sleep(5)

    if not verified:
      logger.error(
          "Verification failed for finding %s. Skipping fix.", finding_id
      )
      sanitize_exploit_and_artifacts(
          repo_dir, codemender_home=os.path.dirname(state_db_path)
      )
      return

    # Sanitize any accidental package/build caches from .exploit before fix starts
    sanitize_exploit_and_artifacts(
        repo_dir, codemender_home=os.path.dirname(state_db_path)
    )
  else:
    logger.info(
        "Skipping 'cm verify' for finding %s (skip_verify=True). Proceeding"
        " directly to fix.",
        finding_id,
    )

  # 3. Apply Automated Fix (Executes 'cm fix' with up to 3 attempts)
  max_fix_attempts = 3
  fixed = False
  for attempt in range(1, max_fix_attempts + 1):
    logger.info(
        "Applying fix for finding %s (Attempt %d/%d)...",
        finding_id,
        attempt,
        max_fix_attempts,
    )
    # Ensure a clean workspace before each fix attempt
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
    clean_workspace(repo_dir)
    for port in get_cleanup_ports(config=config):
      free_port(port)

    fix_cmd = build_cm_command(
        cm_binary, "fix", finding_id, cli_version=cli_version
    )
    fix_res = run_command(
        fix_cmd,
        cwd=repo_dir,
        env=scrubbed_env,
        check=False,
    )
    token_usage = getattr(fix_res, "token_usage", None)
    if isinstance(token_usage, dict):
      accumulate_model_token_usage(worker_token_usage, fix_model, token_usage)

    for port in get_cleanup_ports(config=config):
      free_port(port)

    finding_status = get_finding_status(state_db_path, finding_id)

    if fix_res.returncode == 0 and finding_status == "FIXED":
      logger.info("Successfully applied fix for finding %s.", finding_id)
      fixed = True
      break
    else:
      logger.warning(
          "Attempt %d failed to fix finding %s (status: %s, returncode: %d).",
          attempt,
          finding_id,
          finding_status,
          fix_res.returncode,
      )
      if attempt < max_fix_attempts:
        time.sleep(5)

  if not fixed:
    logger.warning(
        "Fix failed for finding %s (status: %s)", finding_id, finding_status
    )
    return

  # 4. Surgical Git Staging 3-Tier Fallback
  # Extract patch metadata from local state.db patches table
  edited_files = []
  target_file = None
  patch_diff = ""
  try:
    with closing(sqlite3.connect(state_db_path)) as conn:
      cursor = conn.cursor()
      cursor.execute(
          "SELECT edited_files, target_file, diff FROM patches WHERE"
          " finding_id = ?",
          (finding_id,),
      )
      row = cursor.fetchone()
      if row:
        try:
          edited_files = json.loads(row[0]) if row[0] else []
        except Exception:
          edited_files = []
        target_file = row[1]
        patch_diff = row[2] or ""
  except Exception as e:
    logger.warning("Failed to query patches table for staging: %s", e)

  staged = False
  # Tier 1: Stage explicit edited_files recorded by the agent in patches table
  if edited_files and isinstance(edited_files, list):
    valid_files = filter_stageable_files(repo_dir, edited_files)
    if valid_files:
      try:
        run_command(["git", "add"] + valid_files, cwd=repo_dir)
        staged = True
        logger.info(
            "Surgical Git Staging (Tier 1 - edited_files): %s", valid_files
        )
      except Exception as e:
        logger.warning(
            "Failed to stage edited_files %s (falling back): %s", valid_files, e
        )

  # Tier 2: Stage target_file recorded in patches table
  if not staged and target_file:
    valid_targets = filter_stageable_files(repo_dir, [target_file])
    if valid_targets:
      try:
        run_command(["git", "add"] + valid_targets, cwd=repo_dir)
        staged = True
        logger.info(
            "Surgical Git Staging (Tier 2 - target_file): %s", valid_targets
        )
      except Exception as e:
        logger.warning(
            "Failed to stage target_file %s (falling back): %s", valid_targets, e
        )

  # Tier 3: Tracked staging + Finding FilePath fallback
  if not staged:
    try:
      run_command(["git", "add", "-u"], cwd=repo_dir, check=False)
      valid_fallbacks = (
          filter_stageable_files(repo_dir, [file_path]) if file_path else []
      )
      if valid_fallbacks:
        run_command(["git", "add"] + valid_fallbacks, cwd=repo_dir, check=False)
      staged = True
      logger.info(
          "Surgical Git Staging (Tier 3 - Fallback): git add -u + %s",
          valid_fallbacks,
      )
    except Exception as e:
      logger.warning("Failed during Tier 3 fallback staging: %s", e)

  # Check if any git modifications are staged
  status_res = run_command(["git", "status", "--porcelain"], cwd=repo_dir)
  if not status_res.stdout.strip():
    logger.warning("No changes detected after fix for finding %s", finding_id)
    return

  # Extract unified git diff if not captured in patches table
  if not patch_diff:
    diff_res = run_command(["git", "diff", "HEAD"], cwd=repo_dir, check=False)
    patch_diff = diff_res.stdout

  # 5. Route the remediation to the reviewer
  try:
    if suggestion_mode:
      fallback_route = "patch comment" if config.is_fork_pr else "Child PR"
      # Suggestions must be derived before committing: the parser reads the
      # pre-fix content from HEAD, which is still the pull request head commit.
      # Any failure here degrades to the fallback route rather than propagating
      # to the handler below, which would strand the finding with no fix at all.
      try:
        comments, blocker = _build_suggestion_comments(
            finding_id,
            {"severity": severity, "vuln_type": vuln_type, "analysis": analysis},
            repo_dir,
            patch_diff,
            pr_diff_line_ranges or {},
        )
      except Exception as e:  # pylint: disable=broad-exception-caught
        comments, blocker = [], f"suggestion construction failed: {e}"
      if blocker:
        logger.info(
            "Finding %s cannot be offered as a one-click suggestion (%s);"
            " falling back to %s.",
            finding_id,
            blocker,
            fallback_route,
        )
      else:
        review_body = (
            f"### 🛡️ CodeMender proposed a fix for a {severity} `{vuln_type}`\n\n"
            f"**{title}**\n\n"
            f"`{file_path}:{start_line}` · Finding `{finding_id}`\n\n"
            "Commit the inline suggestion(s) in this review to apply the fix"
            " directly to this pull request.\n\n"
            "---\n"
            "*Automatically generated by CodeMender Orchestrator.*"
        )
        review_url = create_pr_review_with_suggestions(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            commit_id=config.target_sha,
            body=review_body,
            comments=comments,
        )
        if review_url:
          return review_url
        logger.warning(
            "Suggestion review was rejected for finding %s; falling back to %s.",
            finding_id,
            fallback_route,
        )

    # The fallback and Child PR routes both build on a dedicated fix branch.
    if suggestion_mode and not config.is_fork_pr and not force_overwrite:
      # The upfront duplicate check was skipped because suggestion mode pushes
      # no branch. Falling back to the Child PR route does push one, so the
      # check has to happen now to avoid clobbering an earlier fallback's work.
      if _skip_if_duplicate_branch_or_pr(
          clean_repo_url,
          token,
          repo_dir,
          branch_name,
          file_path,
          vuln_type,
          start_line,
          finding_id,
          state_db_path,
      ):
        return None

    run_command(["git", "checkout", "-B", branch_name], cwd=repo_dir)
    commit_msg = f"fix(security): resolve {vuln_type} in {file_path}"
    run_command(["git", "commit", "-m", commit_msg], cwd=repo_dir)

    if config.is_fork_pr:
      # Fork PR Scan: Post Markdown review comment on the Fork PR instead of pushing
      logger.info(
          "Fork PR Scan: Posting review comment on PR #%s instead of pushing"
          " branch.",
          config.pr_number,
      )
      # Construct formatted Markdown review comment body with analysis, patch diff, and git apply instructions
      comment_header = (
          "### 🛡️ CodeMender Security Fix Suggestion\n\n"
          f"**Finding ID**: `{finding_id}`\n"
          f"**Title**: {title}\n"
          f"**Severity**: {severity}\n"
          f"**Vulnerability Type**: {vuln_type}\n"
          f"**File**: `{file_path}`\n"
          f"**Start Line**: {start_line}\n\n"
          f"#### Analysis\n{analysis}\n\n"
      )
      comment_body = _fit_fork_comment(
          header=comment_header,
          # Render code diff block with 4-backtick fence to prevent premature closure on embedded markdown/backticks
          diff_section=(
              f"#### Suggested Patch Diff\n````diff\n{patch_diff}\n````\n\n"
          ),
          # Render local git apply snippet with 4-backtick fence
          apply_section=(
              "#### How to Apply Locally\n````bash\ngit apply <<"
              f" 'EOF'\n{patch_diff}\nEOF\n````\n\n"
          ),
          footer="---\n*Automatically generated by CodeMender Orchestrator.*",
      )
      # Submit Markdown review comment to Fork PR via GitHub REST API
      if config.pr_number:
        return create_pr_comment(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            body=comment_body,
        )
      else:
        # Warn if PR number is missing on fork scan
        logger.warning(
            "Fork PR Scan: CODEMENDER_PR_NUMBER not set; cannot post comment."
        )
        return None
    else:
      # Internal Branch / Nightly Scan: Push fix branch to origin
      logger.info("Pushing branch %s...", branch_name)
      push_branch_to_remote(
          repo_dir=repo_dir,
          token=token,
          branch_name=branch_name,
          force=force_overwrite,
      )

      # Dual PR Routing: Child PR vs Mainline PR
      if config.is_pr_scan:
        base_branch = config.pr_head_ref or default_branch
        logger.info(
            "Internal PR Scan: Creating Child PR targeting feature branch"
            " '%s'...",
            base_branch,
        )
        # Add parent PR cross-reference to title and body for bidirectional linkage
        if config.pr_number:
          pr_title = (
              f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
              f" (Child PR for #{config.pr_number})"
          )
          parent_pr_section = (
              f"**Parent PR**: #{config.pr_number} (Branch: `{base_branch}`)\n\n"
          )
        else:
          pr_title = (
              f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
          )
          parent_pr_section = ""
      else:
        base_branch = default_branch
        logger.info(
            "Nightly/Standard Scan: Creating PR targeting default branch"
            " '%s'...",
            base_branch,
        )
        pr_title = (
            f"fix(security): resolve {vuln_type} vulnerability in {file_path}"
        )
        parent_pr_section = ""

      # Construct PR description with parent PR reference
      pr_body = (
          "### CodeMender Security Fix\n\n"
          f"{parent_pr_section}"
          f"**Finding ID**: `{finding_id}`\n"
          f"**Title**: {title}\n"
          f"**Severity**: {severity}\n"
          f"**Vulnerability Type**: {vuln_type}\n"
          f"**File Path**: `{file_path}`\n"
          f"**Start Line**: {start_line}\n\n"
          f"#### Analysis\n{analysis}\n\n"
          "---\n"
          "*Automatically generated by CodeMender Orchestrator.*"
      )

      # Create Pull Request on GitHub with transactional rollback on failure
      try:
        child_pr_url = create_pull_request(
            token=token,
            owner=owner,
            repo=repo_name,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
        )
        if not child_pr_url or child_pr_url == "FAILED":
          raise RuntimeError(f"Failed to create Pull Request for {branch_name}")
      except Exception as pr_err:
        logger.error(
            "PR creation failed for branch %s (%s). Rolling back remote branch to prevent orphan ref...",
            branch_name,
            pr_err,
        )
        delete_remote_branch(clean_repo_url, token, branch_name, cwd=repo_dir)
        raise

      # Post notification comment on Parent PR linking to the generated Child PR
      if (
          config.is_pr_scan
          and config.pr_number
          and child_pr_url
          and child_pr_url != "EXISTING_PR"
      ):
        # Extract Child PR number from URL if available
        child_match = re.search(r"/pull/(\d+)", child_pr_url)
        child_ref = f"#{child_match.group(1)}" if child_match else child_pr_url
        parent_comment = (
            "### 🛡️ CodeMender Security Fix Created\n\n"
            f"CodeMender detected a **{severity}** `{vuln_type}` vulnerability"
            f" in `{file_path}:{start_line}` and generated a proposed fix in"
            f" {child_ref}.\n\n"
            f"- **Child PR**: {child_pr_url}\n"
            f"- **Target Branch**: `{base_branch}`\n"
            f"- **Fix Branch**: `{branch_name}`\n\n"
            "#### Recommended Action\n"
            f"Review and merge {child_ref} into your feature branch"
            f" `{base_branch}` to resolve this finding.\n\n"
            "---\n"
            "*Automatically generated by CodeMender Orchestrator.*"
        )
        logger.info(
            "Posting notification comment on Parent PR #%d linking to Child"
            " PR...",
            config.pr_number,
        )
        create_pr_comment(
            token=token,
            owner=owner,
            repo=repo_name,
            pr_number=config.pr_number,
            body=parent_comment,
        )
      return child_pr_url
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Error creating branch/PR for finding %s: %s", finding_id, e)
    if os.path.exists(state_db_path):
      try:
        with closing(sqlite3.connect(state_db_path)) as conn:
          conn.execute(
              "UPDATE findings SET status = 'PR_CREATION_FAILED', mute_reason = ? WHERE finding_id = ?",
              (f"PR creation or git push failed: {e}", finding_id),
          )
          conn.commit()
      except Exception as db_err:
        logger.warning(
            "Failed to update status to PR_CREATION_FAILED in worker state.db: %s",
            db_err,
        )
    return None
  finally:
    # Always reset workspace back to clean working base ref
    run_command(["git", "checkout", "-f", working_base_ref], cwd=repo_dir)
    clean_workspace(repo_dir)


def _save_and_upload_worker_metadata(
    workspace_dir: str,
    worker_index: int,
    worker_token_usage: dict[str, dict[str, int]],
    metadata_url: Optional[str],
    finding_prs: Optional[dict[str, str]] = None,
) -> None:
  """Saves worker metadata JSON and uploads it to GCS or transit storage."""
  # 1. Validate that metadata destination URL is available
  if not metadata_url:
    logger.error(
        "Failed to resolve metadata signed URL for worker %d; token usage"
        " statistics will be incomplete!",
        worker_index,
    )
    return

  logger.info("Uploading worker %d metadata...", worker_index)
  # 2. Package worker telemetry and token usage dictionary
  worker_metadata = {
      "worker_index": worker_index,
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "token_usage": worker_token_usage,
      "finding_prs": finding_prs or {},
  }
  meta_path = os.path.join(
      workspace_dir, f"worker_{worker_index}_metadata.json"
  )
  try:
    # 3. Write metadata to local JSON file
    with open(meta_path, "w", encoding="utf-8") as f:
      json.dump(worker_metadata, f, indent=2)
    # 4. Upload worker metadata JSON via signed PUT URL or transit storage
    if not upload_to_url(
        meta_path, metadata_url, content_type="application/json"
    ):
      logger.error(
          "Failed to upload worker %d metadata; token usage statistics will be"
          " incomplete!",
          worker_index,
      )
    else:
      logger.info(
          "Successfully uploaded worker %d metadata.", worker_index
      )
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log error if saving or uploading worker telemetry fails
    logger.error(
        "Failed to save or upload worker %d metadata: %s", worker_index, e
    )


def run_worker_pipeline() -> None:
  """Executes Stage 2: Download state, run verify/fix on partition, upload mutated state."""
  config = OrchestratorConfig.from_env()
  worker_index = config.worker_index if config.worker_index is not None else 0
  logger.info("Starting Worker %d", worker_index)

  # Initialize active storage adapter (GCS or GitHub Actions transit adapter)
  adapter = get_storage_adapter(config.storage_mode, config.gcs_bucket)

  # 1. Base Workspace URL Resolution:
  # In GitHub Actions matrix runs, regenerate local file:// URL to match the current worker workspace mount
  base_workspace_url = config.base_workspace_url
  if not base_workspace_url or (
      config.storage_mode == "github_actions"
      and base_workspace_url.startswith("file://")
  ):
    base_workspace_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/workspace_base.tar.gz"
    )

  # 2. Partition URL Resolution:
  # Extract assigned partition URL from list or regenerate via active transit adapter
  partition_url = None
  if config.partition_urls:
    try:
      p_urls = json.loads(config.partition_urls)
      if worker_index < len(p_urls):
        partition_url = p_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not partition_url or (
      config.storage_mode == "github_actions"
      and partition_url.startswith("file://")
  ):
    partition_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/partition_{worker_index}.json"
    )

  # 3. Worker Shard Database PUT URL Resolution:
  # Regenerate local transit shard path in GitHub Actions mode to avoid stale mount paths
  upload_url = None
  if config.upload_urls:
    try:
      u_urls = json.loads(config.upload_urls)
      if worker_index < len(u_urls):
        upload_url = u_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not upload_url or (
      config.storage_mode == "github_actions"
      and upload_url.startswith("file://")
  ):
    upload_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/worker_{worker_index}_state.db",
        method="PUT",
        content_type="application/octet-stream",
    )

  # 4. Worker Token Usage Metadata PUT URL Resolution:
  # Extract or regenerate signed PUT URL for worker token usage metadata upload
  metadata_url = None
  if config.metadata_urls:
    try:
      m_urls = json.loads(config.metadata_urls)
      if worker_index < len(m_urls):
        metadata_url = m_urls[worker_index]
    except Exception:  # pylint: disable=broad-exception-caught
      pass
  if not metadata_url or (
      config.storage_mode == "github_actions"
      and metadata_url.startswith("file://")
  ):
    metadata_url = adapter.generate_signed_url(
        f"scans/{config.scan_id or 'default_scan'}/worker_{worker_index}_metadata.json",
        method="PUT",
        content_type="application/json",
    )

  # Validate that all required transit signed URLs were resolved
  if not base_workspace_url or not partition_url or not upload_url:
    logger.critical(
        "Failed to resolve required URLs for worker %d.", worker_index
    )
    sys.exit(1)

  workspace_dir = config.workspace_dir or os.getcwd()
  repo_url, token = get_github_credentials(config=config)
  clean_repo_url = sanitize_git_url(repo_url)
  owner, repo_name = parse_repo_owner_and_name(clean_repo_url)
  repo_dir = os.path.join(workspace_dir, repo_name)

  # 5. Clone repository and setup target SHA / working base ref
  target_sha = config.target_sha
  default_branch, working_base_ref = _setup_git_and_checkout(
      clean_repo_url,
      token,
      repo_dir,
      workspace_dir,
      target_sha,
      owner,
      repo_name,
      is_pr_scan=config.is_pr_scan,
  )

  # 6. Initialize local sandbox cache environment
  scrubbed_env = get_scrubbed_env(repo_dir=repo_dir)

  # 7. Restore base workspace and download partition slice
  codemender_home = os.path.expanduser("~/.codemender")
  _, finding_ids = _restore_state(
      base_workspace_url,
      partition_url,
      workspace_dir,
      worker_index,
      codemender_home,
  )

  state_db_path = os.path.join(codemender_home, "state.db")
  worker_token_usage: dict[str, dict[str, int]] = {}

  # 7. Handle case where partition slice contains zero findings
  if not finding_ids:
    logger.info("No findings in partition. Exiting.")
    if not upload_to_url(state_db_path, upload_url):
      logger.critical("Failed to upload unmodified database.")
      sys.exit(1)

    _save_and_upload_worker_metadata(
        workspace_dir, worker_index, worker_token_usage, metadata_url
    )
    sys.exit(0)

  # 8. Inject project configurations and verify CLI binary
  inject_codemender_config(repo_dir, config=config)
  cm_binary = shutil.which("cm") or "cm"
  try:
    cm_binary = ensure_cm_binary_version(requested_version=config.binary_version, cm_binary=cm_binary)
    log_cm_version(cm_binary, env=scrubbed_env, cwd=repo_dir)
    validate_model_support(cm_binary=cm_binary, config=config, env=scrubbed_env, cwd=repo_dir)
  except (ValueError, RuntimeError) as e:
    logger.critical("CodeMender CLI version or model validation failed: %s", e)
    sys.exit(1)
  cli_version = config.cli_version

  # 9. Query restored SQLite state.db for finding metadata
  try:
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
    all_findings = parse_findings_json(report_res.stdout)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.critical("Failed to run cm report in worker: %s", e)
    sys.exit(1)

  findings_dict = {f["FindingID"]: f for f in all_findings if "FindingID" in f}

  worker_finding_prs: dict[str, str] = {}

  # 10. Pre-fetch pull request review context shared by every assigned finding
  pr_diff_line_ranges: dict[str, set[int]] = {}
  already_suggested: set[str] = set()
  if (
      config.is_pr_scan
      and config.pr_number
      and resolve_pr_remediation_mode(config) == PR_MODE_REVIEW_SUGGESTION
  ):
    pr_diff_line_ranges = get_pr_diff_line_ranges(
        token, owner, repo_name, config.pr_number
    )
    already_suggested = list_reviewed_finding_ids(
        token, owner, repo_name, config.pr_number
    )
    logger.info(
        "Review suggestion mode: %d file(s) addressable in PR #%d, %d finding(s)"
        " already suggested.",
        len(pr_diff_line_ranges),
        config.pr_number,
        len(already_suggested),
    )

  # 11. Process each assigned finding sequentially (Verify -> Fix -> Stage -> Route)
  for finding_id in finding_ids:
    finding = findings_dict.get(finding_id)
    if not finding:
      logger.warning(
          "Finding %s not found in restored database, skipping.", finding_id
      )
      continue

    # Execute verify, fix, staging, and remediation routing routine for finding
    pr_url = _process_finding(
        finding_id,
        finding,
        repo_dir,
        cm_binary,
        scrubbed_env,
        clean_repo_url,
        token,
        owner,
        repo_name,
        default_branch,
        working_base_ref,
        state_db_path,
        worker_token_usage,
        config=config,
        pr_diff_line_ranges=pr_diff_line_ranges,
        already_suggested=already_suggested,
    )
    # Track generated Pull Request URL for Step Summary linking
    if pr_url and isinstance(pr_url, str) and pr_url.startswith("http"):
      worker_finding_prs[finding_id] = pr_url

  # 12. Upload mutated worker state database shard and token telemetry
  logger.info("Uploading mutated database to transit storage...")
  if not upload_to_url(state_db_path, upload_url):
    logger.error("Failed to upload mutated database.")
    sys.exit(1)

  # Upload worker metadata with accumulated token metrics and finding PR links
  _save_and_upload_worker_metadata(
      workspace_dir,
      worker_index,
      worker_token_usage,
      metadata_url,
      finding_prs=worker_finding_prs,
  )

  # 13. Adjust file permissions on transit directory if running in local container
  transit_dir = os.path.join(workspace_dir, ".codemender_transit")
  if os.path.exists(transit_dir):
    try:
      for root, dirs, files in os.walk(transit_dir):
        for d in dirs:
          os.chmod(os.path.join(root, d), 0o777)
        for f in files:
          os.chmod(os.path.join(root, f), 0o666)
    except Exception:
      pass

  logger.info("Stage 2 (Worker) completed successfully.")
