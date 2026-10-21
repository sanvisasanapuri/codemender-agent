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

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import requests
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from codemender_agent.utils import (
    build_cm_command,
    extract_json_from_output,
    normalize_model_name,
    run_command,
)

logger = logging.getLogger("codemender-orchestrator")


@dataclass
class TokenUsage:
  """Container for accumulated token usage metrics."""

  in_tokens: int = 0
  out_tokens: int = 0
  total_tokens: int = 0

  def add(self, other: "TokenUsage") -> None:
    self.in_tokens += other.in_tokens
    self.out_tokens += other.out_tokens
    self.total_tokens += other.total_tokens

  def to_dict(self) -> Dict[str, int]:
    return {
        "in_tokens": self.in_tokens,
        "out_tokens": self.out_tokens,
        "total_tokens": self.total_tokens,
    }


class CodeMenderCLIAdapter:
  """Adapter isolating CodeMender CLI command construction, execution, and output harvesting."""

  def __init__(
      self, binary_path: Optional[str] = None, cli_version: str = "preview"
  ):
    self.binary_path = binary_path or shutil.which("cm") or "cm"
    self.cli_version = cli_version

  def execute(
      self,
      action: str,
      target_or_id: Optional[str] = None,
      extra_flags: Optional[List[str]] = None,
      cwd: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
      check: bool = True,
      capture_stderr: bool = True,
  ) -> Tuple[subprocess.CompletedProcess, TokenUsage]:
    """Builds and executes a CodeMender CLI command, extracting token usage metrics."""
    cmd = build_cm_command(
        self.binary_path,
        action,
        target_or_id=target_or_id,
        extra_flags=extra_flags,
        cli_version=self.cli_version,
    )
    res = run_command(
        cmd, cwd=cwd, env=env, check=check, capture_stderr=capture_stderr
    )
    usage = TokenUsage()
    if hasattr(res, "token_usage") and isinstance(res.token_usage, dict):
      usage = TokenUsage(
          in_tokens=res.token_usage.get("in_tokens", 0),
          out_tokens=res.token_usage.get("out_tokens", 0),
          total_tokens=res.token_usage.get("total_tokens", 0),
      )
    return res, usage


# Canonical PascalCase finding schema per docs/architecture/guardrails.md Section 6.
# cm CLI 0.7.0 (cl/974628022) switched `cm report --format json` to snake_case keys,
# so both casings are normalized to the canonical form for version-agnostic parsing.
_FINDING_KEY_ALIASES = {
    "finding_id": "FindingID",
    "session_id": "SessionID",
    "title": "Title",
    "file_path": "FilePath",
    "severity": "Severity",
    "confidence": "Confidence",
    "analysis": "Analysis",
    "snippet": "Snippet",
    "vuln_type": "VulnType",
    "vuln_id": "VulnID",
    "fingerprint": "Fingerprint",
    "status": "Status",
    "source_stage": "SourceStage",
    "finding_json": "FindingJSON",
    "updated_at": "UpdatedAt",
    "start_line": "StartLine",
    "end_line": "EndLine",
    "dismiss_reason": "DismissReason",
    "confidence_level": "ConfidenceLevel",
}


def parse_findings_json(json_str: str) -> List[Dict[str, Any]]:
  """Parses `cm report --format json` output normalizing keys to PascalCase."""
  data = extract_json_from_output(json_str)
  if data is None:
    logger.error("No valid JSON array or object found in report.")
    return []

  if isinstance(data, dict):
    findings = data.get("findings", data.get("items", []))
  elif isinstance(data, list):
    findings = data
  else:
    findings = []

  cleaned_findings = []
  for item in findings:
    if not isinstance(item, dict):
      continue
    cleaned = {}
    for k, v in item.items():
      if v == "":
        cleaned[k] = None
      else:
        cleaned[k] = v
      # Mirror snake_case keys onto the canonical PascalCase name. The original
      # key is retained so downstream snake_case readers keep working, and an
      # explicit PascalCase key already present in the payload always wins.
      canonical = _FINDING_KEY_ALIASES.get(k)
      if canonical and canonical not in item:
        cleaned[canonical] = cleaned[k]
    cleaned_findings.append(cleaned)

  return cleaned_findings


def extract_session_id(find_stdout: str) -> Optional[str]:
  """Extracts the CodeMender session ID from 'cm find' output."""
  # Match UUID format session ID (e.g. Session: f7f7b492-3564-4dc0-bc8f-2020554ebe24)
  match = re.search(
      r"Session:\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
      find_stdout,
      re.IGNORECASE,
  )
  if match:
    return match.group(1)
  return None


def log_cm_version(
    cm_binary: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> Optional[str]:
  """Runs `cm --version` and logs the CodeMender CLI binary version.

  Args:
    cm_binary: Path or name of the cm executable.
    env: Environment variables for the subprocess.
    cwd: Working directory for running the command.

  Returns:
    The output version string if successfully retrieved, or None.
  """
  bin_path = cm_binary or shutil.which("cm") or "cm"
  try:
    res = run_command(
        [bin_path, "--version"],
        cwd=cwd,
        env=env,
        check=False,
        capture_stderr=True,
    )
    if res.returncode == 0:
      version_str = res.stdout.strip()
      if version_str:
        logger.info("CodeMender CLI version: %s", version_str)
        return version_str
      logger.warning("CodeMender CLI returned empty version output.")
    else:
      logger.warning(
          "Failed to retrieve CodeMender CLI version (exit code %d): %s",
          res.returncode,
          res.stderr.strip() if getattr(res, "stderr", None) else "",
      )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.warning("Error checking CodeMender CLI version: %s", e)
  return None

AR_DOWNLOAD_BASE_URL = (
    "https://artifactregistry.googleapis.com/download/v1/"
    "projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files"
)
DEFAULT_BINARY_VERSION = "latest"


def extract_cm_semver(version_output: Optional[str]) -> Optional[str]:
  if not version_output:
    return None
  m = re.search(r"\bv?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b", version_output)
  return m.group(1) if m else None


def get_installed_cm_semver(cm_binary: Optional[str] = None, env=None, cwd=None) -> Optional[str]:
  bin_path = cm_binary or shutil.which("cm") or "cm"
  try:
    res = subprocess.run([bin_path, "--version"], cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=15)
    if res.returncode == 0:
      return extract_cm_semver(res.stdout)
  except Exception:
    pass
  return None


def _get_gcp_access_token() -> Optional[str]:
  env_token = os.environ.get("CODEMENDER_AR_ACCESS_TOKEN")
  if env_token and env_token.strip():
    return env_token.strip()
  try:
    resp = requests.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"},
        timeout=3,
    )
    if resp.status_code == 200:
      return str(resp.json().get("access_token") or "").strip() or None
  except Exception:
    pass
  gcloud_bin = shutil.which("gcloud")
  if gcloud_bin:
    try:
      res = subprocess.run([gcloud_bin, "auth", "print-access-token"], capture_output=True, text=True, check=False, timeout=10)
      if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    except Exception:
      pass
  return None


def fetch_latest_cm_release_info(access_token: Optional[str] = None):
  token = access_token or _get_gcp_access_token()
  headers = {"Authorization": f"Bearer {token}"} if token else {}
  url = f"{AR_DOWNLOAD_BASE_URL}/cm%3Astable%3Astable.json:download?alt=media"
  resp = requests.get(url, headers=headers, timeout=15)
  resp.raise_for_status()
  manifest = resp.json()
  version = str(manifest.get("version") or "").strip()
  sha256_hex = (manifest.get("platforms") or {}).get("linux-amd64")
  return version, sha256_hex


def download_cm_binary_version(version: str, dest_dir: str, expected_sha256: Optional[str] = None, access_token: Optional[str] = None) -> str:
  clean_ver = version.strip()
  if clean_ver.startswith("v") and len(clean_ver) > 1 and clean_ver[1].isdigit():
    clean_ver = clean_ver[1:]
  if not re.match(r"^[0-9A-Za-z._-]+$", clean_ver):
    raise ValueError(f"Invalid CodeMender binary version identifier: '{version}'")
  token = access_token or _get_gcp_access_token()
  headers = {"Authorization": f"Bearer {token}"} if token else {}
  url = f"{AR_DOWNLOAD_BASE_URL}/cm%3A{clean_ver}%3Acm-linux-amd64.zip:download?alt=media"
  logger.info("Downloading CodeMender CLI version '%s' from Artifact Registry...", clean_ver)
  resp = requests.get(url, headers=headers, timeout=60)
  if resp.status_code != 200:
    raise RuntimeError(f"Failed to download CodeMender CLI version '{clean_ver}' (HTTP {resp.status_code}).")
  payload = resp.content
  if expected_sha256:
    actual = hashlib.sha256(payload).hexdigest()
    if actual.lower() != expected_sha256.strip().lower():
      raise RuntimeError(f"SHA-256 mismatch for cm {clean_ver}: expected {expected_sha256}, got {actual}")
  os.makedirs(dest_dir, exist_ok=True)
  zip_path = os.path.join(dest_dir, f"cm-{clean_ver}.zip")
  with open(zip_path, "wb") as f:
    f.write(payload)
  try:
    with zipfile.ZipFile(zip_path, "r") as zf:
      zf.extract("cm", path=dest_dir)
  finally:
    if os.path.exists(zip_path):
      os.remove(zip_path)
  cm_out = os.path.join(dest_dir, "cm")
  os.chmod(cm_out, 0o755)
  return cm_out


def ensure_cm_binary_version(requested_version: Optional[str] = None, cm_binary: Optional[str] = None, install_dir: Optional[str] = None) -> str:
  env_req = os.environ.get("CODEMENDER_BINARY_VERSION")
  raw_req = requested_version if requested_version is not None else (env_req or DEFAULT_BINARY_VERSION)
  req = raw_req.strip().lower()
  bin_path = cm_binary or shutil.which("cm") or "cm"
  installed_semver = get_installed_cm_semver(bin_path)
  if req in ("installed", "bundled", "local", "skip"):
    logger.info("CodeMender CLI version resolution: requested='%s', using pre-installed container binary '%s' (%s).", raw_req, installed_semver or "unknown", bin_path)
    return bin_path
  is_real_binary = bool(bin_path and os.path.exists(bin_path))
  if not is_real_binary and env_req is None and (requested_version is None or req in ("latest", "stable", "default", "")):
    return bin_path
  if install_dir:
    target_dir = install_dir
  elif is_real_binary and os.access(os.path.dirname(os.path.abspath(bin_path)), os.W_OK):
    target_dir = os.path.dirname(os.path.abspath(bin_path))
  elif os.path.isdir("/usr/local/bin") and os.access("/usr/local/bin", os.W_OK):
    target_dir = "/usr/local/bin"
  else:
    target_dir = os.path.join(tempfile.gettempdir(), "codemender-cli-bin")

  if req in ("latest", "stable", "default", ""):
    try:
      token = _get_gcp_access_token()
      latest_ver, sha256_hex = fetch_latest_cm_release_info(access_token=token)
      logger.info(
          "CodeMender CLI version resolution: requested='%s', container_installed='%s', upstream_stable_manifest='%s' (sha256=%s)",
          raw_req, installed_semver or "unknown", latest_ver, (sha256_hex[:12] + "...") if sha256_hex else "n/a",
      )
      if installed_semver == latest_ver:
        logger.info("CodeMender CLI binary is already at latest version %s (%s).", latest_ver, bin_path)
        return bin_path
      new_bin = download_cm_binary_version(latest_ver, target_dir, expected_sha256=sha256_hex, access_token=token)
      if target_dir not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{target_dir}{os.pathsep}{os.environ.get('PATH', '')}"
      return new_bin
    except Exception as e:
      if installed_semver:
        logger.info("Using pre-installed CodeMender CLI version %s (%s).", installed_semver, e)
        return bin_path
      return bin_path

  target_ver = raw_req.strip()
  if target_ver.startswith("v") and len(target_ver) > 1 and target_ver[1].isdigit():
    target_ver = target_ver[1:]
  logger.info("CodeMender CLI version resolution: requested='%s', container_installed='%s'", target_ver, installed_semver or "unknown")
  if installed_semver == target_ver:
    logger.info("CodeMender CLI binary already matches requested version %s (%s).", target_ver, bin_path)
    return bin_path
  token = _get_gcp_access_token()
  new_bin = download_cm_binary_version(target_ver, target_dir, access_token=token)
  if target_dir not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = f"{target_dir}{os.pathsep}{os.environ.get('PATH', '')}"
  return new_bin


def parse_supported_models_from_help(help_text: str):
  """Dynamically parses supported models and default model from `cm find --help`."""
  if not help_text:
    return [], None
  match = re.search(
      r"--model\s+string\s+.*?\(e\.g\.\s*(.+?)\)\s*\(default\s+\"([^\"]+)\"\)",
      help_text,
      re.DOTALL,
  )
  if not match:
    default_match = re.search(r"--model\s+string\s+.*?\(default\s+\"([^\"]+)\"\)", help_text)
    default_model = default_match.group(1).strip() if default_match else None
    return ([default_model] if default_model else []), default_model
  raw_models, default_model = match.group(1), match.group(2).strip() or None
  models = []
  for item in raw_models.split(","):
    cleaned = re.sub(r"\s*\([^)]*\)", "", item).strip()
    if cleaned and cleaned not in models:
      models.append(cleaned)
  if default_model and default_model not in models:
    models.append(default_model)
  return models, default_model


def get_supported_models(cm_binary: Optional[str] = None, env=None, cwd=None):
  """Queries the active `cm` binary dynamically for supported models and its default model."""
  bin_path = cm_binary or shutil.which("cm") or "cm"
  try:
    res = subprocess.run([bin_path, "find", "--help"], cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=15)
    combined = f"{res.stdout or ''}\n{res.stderr or ''}"
    if "--model" in combined:
      return parse_supported_models_from_help(combined)
  except Exception:
    pass
  return [], None


def validate_model_support(cm_binary: Optional[str] = None, config=None, env=None, cwd=None):
  """Dynamically validates configured models against the active `cm` binary without hardcoded lists."""
  supported_models, default_model = get_supported_models(cm_binary, env=env, cwd=cwd)
  effective_default = default_model or "default"
  if config is not None:
    raw_models = {
        "CODEMENDER_MODEL": normalize_model_name(getattr(config, "model", None)),
        "CODEMENDER_FIND_MODEL": normalize_model_name(getattr(config, "find_model", None)),
        "CODEMENDER_VERIFY_MODEL": normalize_model_name(getattr(config, "verify_model", None)),
        "CODEMENDER_FIX_MODEL": normalize_model_name(getattr(config, "fix_model", None)),
    }
  else:
    raw_models = {
        "CODEMENDER_MODEL": normalize_model_name(os.environ.get("CODEMENDER_MODEL")),
        "CODEMENDER_FIND_MODEL": normalize_model_name(os.environ.get("CODEMENDER_FIND_MODEL")),
        "CODEMENDER_VERIFY_MODEL": normalize_model_name(os.environ.get("CODEMENDER_VERIFY_MODEL")),
        "CODEMENDER_FIX_MODEL": normalize_model_name(os.environ.get("CODEMENDER_FIX_MODEL")),
    }
  if supported_models:
    unsupported = [f"{k}='{v}'" for k, v in raw_models.items() if v and v not in supported_models]
    if unsupported:
      err_msg = (
          f"Unsupported CodeMender model configuration ({', '.join(unsupported)}). "
          f"Supported models reported by the active CodeMender CLI binary are: {', '.join(supported_models)} "
          f"(binary default: {effective_default})."
      )
      logger.error(err_msg)
      raise ValueError(err_msg)
  base_model = raw_models["CODEMENDER_MODEL"] or effective_default
  if default_model:
    os.environ["CODEMENDER_RESOLVED_DEFAULT_MODEL"] = default_model
  resolved = {
      "default": effective_default,
      "find": raw_models["CODEMENDER_FIND_MODEL"] or base_model,
      "verify": raw_models["CODEMENDER_VERIFY_MODEL"] or base_model,
      "fix": raw_models["CODEMENDER_FIX_MODEL"] or base_model,
  }
  logger.info(
      "CodeMender model support verified (binary_default='%s', find='%s', verify='%s', fix='%s').",
      effective_default, resolved["find"], resolved["verify"], resolved["fix"],
  )
  return resolved
