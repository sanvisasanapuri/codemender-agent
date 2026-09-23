#!/usr/bin/env python3
"""CodeMender Orchestrator Entrypoint with Jenkins / Universal CI CLI flags."""
import argparse
import logging
import os
import sys

from codemender_agent.runners.aggregate import run_aggregate_pipeline
from codemender_agent.runners.scan import run_scan_pipeline
from codemender_agent.runners.sequential import run_sequential_pipeline
from codemender_agent.runners.worker import run_worker_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

def main() -> None:
  parser = argparse.ArgumentParser(description="CodeMender Orchestrator")
  parser.add_argument("--pr-number", type=str, default=None)
  parser.add_argument("--branch", type=str, default=None)
  parser.add_argument("--base-branch", type=str, default=None)
  parser.add_argument("--repo", type=str, default=None)
  args, _ = parser.parse_known_args()

  if args.pr_number:
    os.environ["CODEMENDER_IS_PR_SCAN"] = "true"
    os.environ["CODEMENDER_PR_NUMBER"] = str(args.pr_number)
  if args.branch:
    os.environ["CODEMENDER_PR_HEAD_REF"] = args.branch
  if args.base_branch:
    os.environ["CODEMENDER_PR_BASE_REF"] = args.base_branch
  if args.repo:
    os.environ["GITHUB_REPO_URL"] = args.repo if args.repo.startswith("http") else f"https://github.com/{args.repo}.git"

  run_mode = os.environ.get("CODEMENDER_RUN_MODE", "sequential").lower()
  if run_mode == "sequential":
    run_sequential_pipeline()
  elif run_mode == "scan":
    run_scan_pipeline()
  elif run_mode == "worker":
    run_worker_pipeline()
  elif run_mode == "aggregate":
    run_aggregate_pipeline()
  else:
    run_sequential_pipeline()

if __name__ == "__main__":
  main()
