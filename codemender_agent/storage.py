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

"""Cloud and Transit Storage operations and report upload utilities for CodeMender Agent."""

from abc import ABC, abstractmethod
import datetime
import logging
import os
import re
import shutil
from typing import List, Optional
import requests


# pylint: disable=unused-argument
class DummyStorage:
  """Dummy fallback for local developer/unit testing environments."""

  # Mock Blob representing a single GCS object
  class Blob:

    def upload_from_filename(self, *args, **kwargs):
      # No-op mock upload for tests
      pass

    def download_to_filename(self, *args, **kwargs):
      # No-op mock download for tests
      pass

    def generate_signed_url(self, *args, **kwargs):
      # Mock URL generator returning empty string
      return ""

  # Mock Bucket representing a GCS container
  class Bucket:

    def blob(self, *args, **kwargs):
      # Return mock Blob instance
      return DummyStorage.Blob()

    def list_blobs(self, *args, **kwargs):
      # Return empty mock blob list
      return []

  # Mock Client representing GCS client session
  class Client:

    def __init__(self, *args, **kwargs):
      # Initialize mock client
      pass

    def bucket(self, *args, **kwargs):
      # Return mock Bucket instance
      return DummyStorage.Bucket()


# pylint: enable=unused-argument

try:
  from google.cloud import storage
except ImportError:
  storage = DummyStorage

logger = logging.getLogger("codemender-orchestrator")


def _get_local_storage_path(bucket_name: str, blob_name: str) -> str:
  storage_dir = os.environ.get(
      "CODEMENDER_LOCAL_STORAGE_DIR", "/tmp/codemender_local_storage"
  )
  return os.path.join(storage_dir, bucket_name, blob_name)


def _resolve_service_account_email(client) -> Optional[str]:
  """Resolves active service account email for GCS signed URL generation."""
  env_email = os.environ.get("GOOGLE_SERVICE_ACCOUNT_EMAIL")
  if env_email:
    return env_email

  creds_email = getattr(
      getattr(client, "_credentials", None), "service_account_email", None
  )
  if creds_email and creds_email != "default":
    return creds_email

  # In Compute Engine / Cloud Run token-only environments, resolve 'default' via Metadata Server
  try:
    resp = requests.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        headers={"Metadata-Flavor": "Google"},
        timeout=2,
    )
    if resp.status_code == 200 and resp.text.strip():
      return resp.text.strip()
  except Exception:
    pass

  return None


def _generate_gcs_v4_signed_url(
    bucket_name: str,
    blob_name: str,
    expiration_days: int = 3,
    method: str = "GET",
    content_type: Optional[str] = None,
) -> Optional[str]:
  """Generates a temporary V4 Signed URL for direct GCS object download or upload with SA impersonation."""
  try:
    # 1. Initialize Google Cloud Storage Client and target blob
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    # 2. Configure V4 signing arguments with specified expiration and HTTP method
    signing_kwargs = {
        "version": "v4",
        "expiration": datetime.timedelta(days=expiration_days),
        "method": method,
    }
    if content_type:
      signing_kwargs["content_type"] = content_type

    # 3. Handle service account resolution and token impersonation in token-only runtime environments
    if hasattr(client, "_credentials"):
      sa_email = _resolve_service_account_email(client)
      if sa_email:
        try:
          from google.auth import credentials as auth_credentials

          is_signing = isinstance(
              client._credentials, auth_credentials.Signing
          )
        except Exception:  # pylint: disable=broad-exception-caught
          is_signing = False

        # If the active credentials cannot sign directly (e.g. metadata token on Cloud Run), impersonate SA
        if not is_signing:
          try:
            from google.auth import impersonated_credentials

            signing_creds = impersonated_credentials.Credentials(
                source_credentials=client._credentials,
                target_principal=sa_email,
                target_scopes=[
                    "https://www.googleapis.com/auth/devstorage.read_write"
                ],
            )
            signing_kwargs["credentials"] = signing_creds
          except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Failed to create impersonated credentials for %s: %s",
                sa_email,
                e,
            )

    # 4. Generate and return the V4 signed URL
    url = blob.generate_signed_url(**signing_kwargs)
    return url
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error(
        "Failed to generate signed URL for gs://%s/%s: %s",
        bucket_name,
        blob_name,
        e,
    )
  return None


class TransitStorageAdapter(ABC):
  """Abstract interface for transit state and artifact storage."""

  @abstractmethod
  def upload_file(
      self,
      local_path: str,
      dest_blob_name: str,
      content_type: Optional[str] = None,
  ) -> bool:
    """Uploads a local file to transit storage."""
    pass

  @abstractmethod
  def download_file(self, dest_local_path: str, src_blob_name: str) -> bool:
    """Downloads a file from transit storage to a local path."""
    pass

  @abstractmethod
  def list_blobs(self, prefix: str = "") -> List[str]:
    """Lists blob names matching prefix."""
    pass

  @abstractmethod
  def generate_signed_url(
      self,
      blob_name: str,
      expiration_days: int = 3,
      method: str = "GET",
      content_type: Optional[str] = None,
  ) -> Optional[str]:
    """Generates an access/upload URL for the given blob name."""
    pass

  @abstractmethod
  def upload_and_sign_report(
      self, local_file_path: str, dest_blob_name: str
  ) -> Optional[str]:
    """Uploads report and returns signed URL."""
    pass


class GCSTransitStorageAdapter(TransitStorageAdapter):
  """Google Cloud Storage implementation of TransitStorageAdapter."""

  def __init__(self, bucket_name: Optional[str] = None):
    self.bucket_name = bucket_name or os.environ.get("CODEMENDER_GCS_BUCKET", "")

  def upload_file(
      self,
      local_path: str,
      dest_blob_name: str,
      content_type: Optional[str] = None,
  ) -> bool:
    # 1. Verify local file exists on disk
    if not os.path.exists(local_path):
      logger.error("Local file not found for upload: %s", local_path)
      return False
    try:
      # 2. Upload file to GCS destination blob
      client = storage.Client()
      bucket = client.bucket(self.bucket_name)
      blob = bucket.blob(dest_blob_name)
      logger.info(
          "Uploading %s to gs://%s/%s...",
          local_path,
          self.bucket_name,
          dest_blob_name,
      )
      # Stream local file content to remote GCS blob
      blob.upload_from_filename(local_path, content_type=content_type)
      return True
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Log upload failure details
      logger.error("Failed to upload %s to GCS: %s", local_path, e)
      return False

  def download_file(self, dest_local_path: str, src_blob_name: str) -> bool:
    try:
      # 1. Fetch blob reference from GCS bucket
      client = storage.Client()
      bucket = client.bucket(self.bucket_name)
      blob = bucket.blob(src_blob_name)
      logger.info(
          "Downloading gs://%s/%s to %s...",
          self.bucket_name,
          src_blob_name,
          dest_local_path,
      )
      # 2. Ensure parent directory exists and download blob
      os.makedirs(os.path.dirname(dest_local_path), exist_ok=True)
      blob.download_to_filename(dest_local_path)
      return True
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Log error and return failure status if GCS download fails
      logger.error(
          "Failed to download gs://%s/%s from GCS: %s",
          self.bucket_name,
          src_blob_name,
          e,
      )
      return False

  def list_blobs(self, prefix: str = "") -> List[str]:
    try:
      # Query GCS bucket for blobs matching prefix filter
      client = storage.Client()
      bucket = client.bucket(self.bucket_name)
      blobs = bucket.list_blobs(prefix=prefix)
      return [blob.name for blob in blobs]
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Log error and return empty list on listing failure
      logger.error(
          "Failed to list GCS blobs in bucket %s with prefix %s: %s",
          self.bucket_name,
          prefix,
          e,
      )
      return []

  def generate_signed_url(
      self,
      blob_name: str,
      expiration_days: int = 3,
      method: str = "GET",
      content_type: Optional[str] = None,
  ) -> Optional[str]:
    """Generates a temporary V4 Signed URL for direct GCS object download or upload."""
    return _generate_gcs_v4_signed_url(
        bucket_name=self.bucket_name,
        blob_name=blob_name,
        expiration_days=expiration_days,
        method=method,
        content_type=content_type,
    )

  def upload_and_sign_report(
      self, local_file_path: str, dest_blob_name: str
  ) -> Optional[str]:
    if not os.path.exists(local_file_path):
      logger.error("Local report file not found at: %s", local_file_path)
      return None
    try:
      client = storage.Client()
      bucket = client.bucket(self.bucket_name)
      blob = bucket.blob(dest_blob_name)

      logger.info(
          "Uploading report %s to gs://%s/%s...",
          local_file_path,
          self.bucket_name,
          dest_blob_name,
      )
      blob.upload_from_filename(local_file_path, content_type="text/html")

      return self.generate_signed_url(
          dest_blob_name,
          method="GET",
          expiration_days=3,
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error("Failed to upload report: %s", e)
    return None


class LocalStorageAdapter(TransitStorageAdapter):
  """Local filesystem storage adapter simulating GCS bucket directories."""

  def __init__(
      self,
      storage_dir: Optional[str] = None,
      bucket_name: Optional[str] = None,
  ):
    # 1. Resolve local mock storage root directory
    self.storage_dir = (
        storage_dir
        or os.environ.get(
            "CODEMENDER_LOCAL_STORAGE_DIR", "/tmp/codemender_local_storage"
        )
    )
    # 2. Resolve mock GCS bucket name
    self.bucket_name = (
        bucket_name
        or os.environ.get("CODEMENDER_GCS_BUCKET", "local_bucket")
    )

  def _get_path(self, blob_name: str) -> str:
    return os.path.join(self.storage_dir, self.bucket_name, blob_name)

  def upload_file(
      self,
      local_path: str,
      dest_blob_name: str,
      content_type: Optional[str] = None,
  ) -> bool:
    # 1. Check local source file existence
    if not os.path.exists(local_path):
      logger.error("Local file not found for upload: %s", local_path)
      return False
    # 2. Resolve destination mock filesystem path and copy
    dest_path = self._get_path(dest_blob_name)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(local_path, dest_path)
    return True

  def download_file(self, dest_local_path: str, src_blob_name: str) -> bool:
    # 1. Resolve source mock path and verify existence
    src_path = self._get_path(src_blob_name)
    if not os.path.exists(src_path):
      return False
    # 2. Copy source mock file to local destination
    os.makedirs(os.path.dirname(dest_local_path), exist_ok=True)
    shutil.copy(src_path, dest_local_path)
    return True

  def list_blobs(self, prefix: str = "") -> List[str]:
    # 1. Traverse mock bucket directory
    bucket_dir = os.path.join(self.storage_dir, self.bucket_name)
    if not os.path.exists(bucket_dir):
      return []
    blobs = []
    for root, _, files in os.walk(bucket_dir):
      for file in files:
        full_path = os.path.join(root, file)
        rel_path = os.path.relpath(full_path, bucket_dir)
        # 2. Filter matching prefix relative paths
        if not prefix or rel_path.startswith(prefix) or prefix in rel_path:
          blobs.append(rel_path)
    return sorted(blobs)

  def generate_signed_url(
      self,
      blob_name: str,
      expiration_days: int = 3,
      method: str = "GET",
      content_type: Optional[str] = None,
  ) -> Optional[str]:
    # Return file:// schema URL for local file path
    dest_path = self._get_path(blob_name)
    return f"file://{dest_path}"

  def upload_and_sign_report(
      self, local_file_path: str, dest_blob_name: str
  ) -> Optional[str]:
    # 1. Validate local report file existence
    if not os.path.exists(local_file_path):
      logger.error("Local report file not found at: %s", local_file_path)
      return None
    # 2. Copy report to mock storage destination and return file:// URL
    dest_path = self._get_path(dest_blob_name)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(local_file_path, dest_path)
    return self.generate_signed_url(dest_blob_name)


class GitHubActionsTransitStorageAdapter(TransitStorageAdapter):
  """GitHub Actions artifact and transit directory adapter (.codemender_transit/)."""

  def __init__(self, transit_dir: Optional[str] = None, base_dir: Optional[str] = None):
    if transit_dir:
      self.transit_dir = transit_dir
    elif base_dir:
      self.transit_dir = os.path.join(base_dir, ".codemender_transit")
    else:
      self.transit_dir = (
          os.environ.get("CODEMENDER_TRANSIT_DIR")
          or os.path.join(os.environ.get("WORKSPACE_DIR", os.getcwd()), ".codemender_transit")
      )
    self.base_dir = os.path.join(self.transit_dir, "base")
    self.shards_dir = os.path.join(self.transit_dir, "shards")

  def _resolve_dest_path(self, blob_name: str) -> str:
    basename = os.path.basename(blob_name)
    worker_match = re.search(r"worker_(\d+)", blob_name)
    if worker_match and (basename.endswith(".db") or basename.endswith(".json")):
      worker_idx = worker_match.group(1)
      return os.path.join(self.shards_dir, f"worker_{worker_idx}", basename)
    if basename in ["workspace_base.tar.gz", "scan_metadata.json", "manifest.json"] or basename.startswith("partition_"):
      return os.path.join(self.base_dir, basename)
    return os.path.join(self.transit_dir, blob_name)

  def upload_file(
      self,
      local_path: str,
      dest_blob_name: str,
      content_type: Optional[str] = None,
  ) -> bool:
    if not os.path.exists(local_path):
      logger.error("Local file not found for upload: %s", local_path)
      return False
    dest_path = self._resolve_dest_path(dest_blob_name)
    if os.path.abspath(local_path) == os.path.abspath(dest_path):
      return True
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(local_path, dest_path)
    return True

  def download_file(self, dest_local_path: str, src_blob_name: str) -> bool:
    """Downloads a file from transit storage, checking standard subdirectories and recursive shard paths."""
    # 1. Build candidate paths in order of specificity (shards, transit base, and direct paths)
    candidate_paths = [
        self._resolve_dest_path(src_blob_name),
        os.path.join(self.transit_dir, src_blob_name),
        os.path.join(self.base_dir, os.path.basename(src_blob_name)),
        os.path.join(self.shards_dir, os.path.basename(src_blob_name)),
    ]

    # 2. Search shards directory recursively for worker-uploaded DB shards and metadata
    basename = os.path.basename(src_blob_name)
    if os.path.exists(self.shards_dir):
      for root, _, files in os.walk(self.shards_dir):
        if basename in files:
          candidate_paths.append(os.path.join(root, basename))

    # 3. Copy the first existing candidate path to the destination local path
    for src_path in candidate_paths:
      if os.path.exists(src_path):
        os.makedirs(os.path.dirname(dest_local_path), exist_ok=True)
        shutil.copy(src_path, dest_local_path)
        return True
    return False

  def list_blobs(self, prefix: str = "") -> List[str]:
    # 1. Return empty list if transit folder does not exist
    if not os.path.exists(self.transit_dir):
      return []
    blobs = []
    # 2. Walk transit directory recursively to collect relative paths
    for root, _, files in os.walk(self.transit_dir):
      for file in files:
        full_path = os.path.join(root, file)
        rel_path = os.path.relpath(full_path, self.transit_dir)
        # Filter files matching given prefix
        if not prefix or prefix in rel_path or rel_path.startswith(prefix) or file.startswith(prefix):
          blobs.append(rel_path)
    return sorted(list(set(blobs)))

  def generate_signed_url(
      self,
      blob_name: str,
      expiration_days: int = 3,
      method: str = "GET",
      content_type: Optional[str] = None,
  ) -> Optional[str]:
    # Resolve transit destination path and return absolute file:// URL
    dest_path = self._resolve_dest_path(blob_name)
    return f"file://{os.path.abspath(dest_path)}"

  def upload_and_sign_report(
      self, local_file_path: str, dest_blob_name: str
  ) -> Optional[str]:
    # 1. Verify local report file existence
    if not os.path.exists(local_file_path):
      logger.error("Local report file not found at: %s", local_file_path)
      return None
    # 2. Copy report to transit directory
    dest_path = os.path.join(self.transit_dir, dest_blob_name)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(local_file_path, dest_path)
    # 3. Also copy report to active workspace directory for artifact pickup
    workspace_dir = os.environ.get("WORKSPACE_DIR", os.getcwd())
    cwd_dest = os.path.join(workspace_dir, os.path.basename(local_file_path))
    if os.path.abspath(local_file_path) != os.path.abspath(cwd_dest):
      try:
        shutil.copy(local_file_path, cwd_dest)
      except Exception:
        pass
    return f"file://{os.path.abspath(dest_path)}"


def get_storage_adapter(
    storage_mode: Optional[str] = None,
    bucket_name: Optional[str] = None,
    base_dir: Optional[str] = None,
    transit_dir: Optional[str] = None,
) -> TransitStorageAdapter:
  """Factory function returning the active TransitStorageAdapter."""
  mode = storage_mode or os.environ.get("CODEMENDER_STORAGE_MODE")
  if mode:
    mode = mode.strip().lower()
  elif os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
    mode = "github_actions"
  elif not (bucket_name or os.environ.get("CODEMENDER_GCS_BUCKET")):
    mode = "local"
  else:
    mode = "gcs"

  if mode == "github_actions":
    return GitHubActionsTransitStorageAdapter(transit_dir=transit_dir, base_dir=base_dir)
  elif mode == "local":
    return LocalStorageAdapter(bucket_name=bucket_name)
  return GCSTransitStorageAdapter(bucket_name=bucket_name)


def generate_gcs_signed_url(
    bucket_name: str,
    blob_name: str,
    expiration_days: int = 3,
    method: str = "GET",
    content_type: Optional[str] = None,
    storage_mode: Optional[str] = None,
) -> Optional[str]:
  """Generates a temporary Signed URL for a GCS blob (supports GET/PUT)."""
  adapter = get_storage_adapter(storage_mode=storage_mode, bucket_name=bucket_name)
  if isinstance(adapter, (LocalStorageAdapter, GitHubActionsTransitStorageAdapter)):
    return adapter.generate_signed_url(
        blob_name, expiration_days=expiration_days, method=method, content_type=content_type
    )

  return _generate_gcs_v4_signed_url(
      bucket_name=bucket_name,
      blob_name=blob_name,
      expiration_days=expiration_days,
      method=method,
      content_type=content_type,
  )


generate_signed_url = generate_gcs_signed_url


def upload_and_sign_report(
    local_file_path: str,
    bucket_name: str,
    dest_blob_name: str,
    storage_mode: Optional[str] = None,
) -> Optional[str]:
  """Uploads a local HTML report to GCS and returns a temporary Signed URL."""
  if not os.path.exists(local_file_path):
    logger.error("Local report file not found at: %s", local_file_path)
    return None
  adapter = get_storage_adapter(storage_mode=storage_mode, bucket_name=bucket_name)
  if isinstance(adapter, (LocalStorageAdapter, GitHubActionsTransitStorageAdapter)):
    return adapter.upload_and_sign_report(local_file_path, dest_blob_name)
  try:
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(dest_blob_name)

    logger.info(
        "Uploading report %s to gs://%s/%s...",
        local_file_path,
        bucket_name,
        dest_blob_name,
    )
    blob.upload_from_filename(local_file_path, content_type="text/html")

    return generate_signed_url(
        bucket_name,
        dest_blob_name,
        method="GET",
        expiration_days=3,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Failed to upload report: %s", e)
  return None


def upload_file_to_gcs(
    local_path: str,
    bucket_name: str,
    dest_blob_name: str,
    storage_mode: Optional[str] = None,
) -> bool:
  """Uploads a local file to GCS using standard credentials or transit adapter."""
  # 1. Verify that the local source file exists
  if not os.path.exists(local_path):
    logger.error("Local file not found for upload: %s", local_path)
    return False
  # 2. Delegate to active storage adapter if local or GitHub Actions mode
  adapter = get_storage_adapter(storage_mode=storage_mode, bucket_name=bucket_name)
  if isinstance(adapter, (LocalStorageAdapter, GitHubActionsTransitStorageAdapter)):
    return adapter.upload_file(local_path, dest_blob_name)
  try:
    # 3. Perform standard GCS SDK blob upload
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(dest_blob_name)
    logger.info(
        "Uploading %s to gs://%s/%s...", local_path, bucket_name, dest_blob_name
    )
    blob.upload_from_filename(local_path)
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Failed to upload %s to GCS: %s", local_path, e)
    return False


def download_file_from_gcs(
    dest_local_path: str,
    bucket_name: str,
    src_blob_name: str,
    storage_mode: Optional[str] = None,
) -> bool:
  """Downloads a file from GCS to a local path using standard credentials or transit adapter."""
  # 1. Delegate to active storage adapter if local or GitHub Actions mode
  adapter = get_storage_adapter(storage_mode=storage_mode, bucket_name=bucket_name)
  if isinstance(adapter, (LocalStorageAdapter, GitHubActionsTransitStorageAdapter)):
    return adapter.download_file(dest_local_path, src_blob_name)
  try:
    # 2. Perform standard GCS SDK blob download
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(src_blob_name)
    logger.info(
        "Downloading gs://%s/%s to %s...",
        bucket_name,
        src_blob_name,
        dest_local_path,
    )
    # Ensure destination parent directory exists on local disk
    os.makedirs(os.path.dirname(dest_local_path), exist_ok=True)
    blob.download_to_filename(dest_local_path)
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log GCS download failure details
    logger.error(
        "Failed to download gs://%s/%s from GCS: %s",
        bucket_name,
        src_blob_name,
        e,
    )
    return False


def list_gcs_blobs(
    bucket_name: str,
    prefix: str,
    storage_mode: Optional[str] = None,
) -> list[str]:
  """Lists blobs in a GCS bucket with a given prefix or transit storage."""
  # 1. Delegate to active storage adapter if local or GitHub Actions mode
  adapter = get_storage_adapter(storage_mode=storage_mode, bucket_name=bucket_name)
  if isinstance(adapter, (LocalStorageAdapter, GitHubActionsTransitStorageAdapter)):
    return adapter.list_blobs(prefix=prefix)
  try:
    # 2. Query GCS SDK for blob listing matching prefix
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blobs = bucket.list_blobs(prefix=prefix)
    return [blob.name for blob in blobs]
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error(
        "Failed to list GCS blobs in bucket %s with prefix %s: %s",
        bucket_name,
        prefix,
        e,
    )
    return []


def download_from_url(url: str, dest_path: str) -> bool:
  """Downloads a file from a given URL (e.g., Signed URL) to a local path."""
  # 1. Handle local file:// URLs directly via local filesystem copy
  if url.startswith("file://"):
    try:
      src_path = url[7:]
      if not os.path.exists(src_path):
        logger.error("Local file not found: %s", src_path)
        return False
      if os.path.abspath(src_path) == os.path.abspath(dest_path):
        return True
      os.makedirs(os.path.dirname(dest_path), exist_ok=True)
      shutil.copy(src_path, dest_path)
      return True
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error(
          "Failed to copy local file from %s to %s: %s", url, dest_path, e
      )
      return False

  # 2. Stream HTTP(S) download from remote Signed URL
  try:
    logger.info("Downloading from URL to %s...", dest_path)
    response = requests.get(url, stream=True, timeout=30)
    response.raise_for_status()
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as f:
      for chunk in response.iter_content(chunk_size=8192):
        f.write(chunk)
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Failed to download from URL %s: %s", url, e)
    return False


def upload_to_url(
    local_path: str, url: str, content_type: Optional[str] = None
) -> bool:
  """Uploads a local file to a given URL (e.g., Signed PUT URL)."""
  # 1. Verify that the local source file exists
  if not os.path.exists(local_path):
    logger.error("Local file not found for upload: %s", local_path)
    return False

  # 2. Handle local file:// URLs directly via filesystem copy
  if url.startswith("file://"):
    try:
      dest_path = url[7:]
      if os.path.abspath(local_path) == os.path.abspath(dest_path):
        return True
      os.makedirs(os.path.dirname(dest_path), exist_ok=True)
      shutil.copy(local_path, dest_path)
      return True
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.error("Failed to copy local file to %s: %s", url, e)
      return False

  # 3. Determine MIME content-type header for HTTP PUT upload
  if not content_type:
    if local_path.endswith(".json"):
      content_type = "application/json"
    else:
      content_type = "application/octet-stream"

  # 4. Stream HTTP PUT request to remote Signed URL
  try:
    logger.info(
        "Uploading %s to URL (Content-Type: %s)...", local_path, content_type
    )
    with open(local_path, "rb") as f:
      # Execute HTTP PUT upload with octet/json stream
      response = requests.put(
          url,
          data=f,
          headers={"Content-Type": content_type},
          timeout=60,
      )
    # Validate successful HTTP status code
    response.raise_for_status()
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Log upload failure details
    logger.error("Failed to upload %s to URL: %s", local_path, e)
    return False
