from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VER = "2022-11-28"
VERACODE_REPO = "veracode"
SAST_PREFIX = "Static Code Analysis - "

# Job name: "policy_scan" (underscore). Step inside it: "policy scan" (space).
# The step uses veracode/uploadandscan-action and then
# veracode/github-actions-integration-helper to post results.
POLICY_JOB_NEEDLE = "policy_scan"


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VER,
    }


_print_lock = threading.Lock()
_rate_limit_lock = threading.Lock()
_rate_limit_pause_until: float = 0.0


def _tprint(*args: Any) -> None:
    with _print_lock:
        print(*args)


def gh_get(url: str, token: str, **kwargs: Any) -> requests.Response:
    """GET with retry on 429/5xx and global thread-safe rate-limit pause."""
    global _rate_limit_pause_until
    headers = _gh_headers(token)
    r: requests.Response | None = None
    for attempt in range(3):
        # If another worker hit the rate limit, wait it out
        with _rate_limit_lock:
            wait_for = max(_rate_limit_pause_until - time.time(), 0)
        if wait_for > 0:
            time.sleep(wait_for)

        r = requests.get(url, headers=headers, timeout=60, **kwargs)

        # Rate-limit awareness: set global pause if we're running low
        remaining = r.headers.get("X-RateLimit-Remaining", "")
        reset_ts = r.headers.get("X-RateLimit-Reset", "")
        if remaining.isdigit() and reset_ts.isdigit() and int(remaining) < 50:
            wait = max(int(reset_ts) - int(time.time()), 0) + 2
            with _rate_limit_lock:
                if time.time() + wait > _rate_limit_pause_until:
                    _rate_limit_pause_until = time.time() + wait
                    _tprint(f"  [RATE LIMIT] {remaining} left, pausing {wait}s globally...")

        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", 60))
            with _rate_limit_lock:
                _rate_limit_pause_until = max(_rate_limit_pause_until, time.time() + retry_after)
            _tprint(f"  [429] Retry in {retry_after}s...")
            time.sleep(retry_after)
            continue
        if r.status_code >= 500 and attempt < 2:
            time.sleep(2 ** attempt)
            continue
        return r
    assert r is not None
    return r


# ---------------------------------------------------------------------------
# Org discovery
# ---------------------------------------------------------------------------

def _discover_orgs_graphql(api_base: str, token: str, enterprise: str) -> list[str]:
    gql_url = (
        "https://api.github.com/graphql"
        if "api.github.com" in api_base
        else f"{api_base.rstrip('/')}/graphql"
    )
    query = """
    query($enterprise: String!, $cursor: String) {
      enterprise(slug: $enterprise) {
        organizations(first: 100, after: $cursor) {
          nodes { login }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
    """
    headers = _gh_headers(token)
    orgs: list[str] = []
    cursor: str | None = None
    while True:
        variables: dict[str, Any] = {"enterprise": enterprise}
        if cursor:
            variables["cursor"] = cursor
        r = requests.post(
            gql_url, headers=headers, timeout=30,
            json={"query": query, "variables": variables},
        )
        if r.status_code != 200:
            break
        data = r.json()
        ent = data.get("data", {}).get("enterprise")
        if not ent or "errors" in data:
            break
        org_data = ent["organizations"]
        orgs.extend(n["login"] for n in org_data.get("nodes", []) if "login" in n)
        pi = org_data.get("pageInfo", {})
        if not pi.get("hasNextPage"):
            break
        cursor = pi.get("endCursor")
    return orgs


def _parse_link_next(link_header: str) -> str | None:
    for part in link_header.split(","):
        if 'rel="next"' in part:
            url_part = part.split(";")[0].strip()
            if url_part.startswith("<") and url_part.endswith(">"):
                return url_part[1:-1]
    return None


def discover_orgs(api_base: str, token: str, enterprise: str | None, orgs_file: str | None) -> list[str]:
    if enterprise:
        orgs = _discover_orgs_graphql(api_base, token, enterprise)
        if orgs:
            print(f"[OK] {len(orgs)} orgs from enterprise")
            return orgs
        raise SystemExit(f"Enterprise '{enterprise}' returned no orgs")

    if orgs_file:
        with open(orgs_file, encoding="utf-8") as f:
            orgs = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        if orgs:
            print(f"[OK] {len(orgs)} orgs from file")
            return orgs
        raise SystemExit(f"No orgs in {orgs_file}")

    orgs: list[str] = []
    url: str | None = f"{api_base}/user/orgs?per_page=100"
    while url:
        r = gh_get(url, token)
        if r.status_code != 200:
            break
        orgs.extend(o["login"] for o in r.json() if "login" in o)
        url = _parse_link_next(r.headers.get("Link", ""))
    if orgs:
        print(f"[OK] {len(orgs)} orgs from user API")
        return orgs
    raise SystemExit("No orgs found")


# ---------------------------------------------------------------------------
# Fetch SAST runs from {org}/veracode
# ---------------------------------------------------------------------------

def fetch_sast_runs(api_base: str, org: str, token: str, max_runs: int) -> list[dict[str, Any]]:
    """Get last N completed 'Static Code Analysis - {repo}' runs."""
    matched: list[dict[str, Any]] = []
    for page in range(1, 6):
        r = gh_get(
            f"{api_base}/repos/{org}/{VERACODE_REPO}/actions/runs",
            token,
            params={"per_page": 100, "page": page, "status": "completed"},
        )
        if r.status_code in (403, 404):
            return matched
        if r.status_code != 200:
            return matched
        runs = r.json().get("workflow_runs", [])
        if not runs:
            break
        for run in runs:
            if (run.get("name") or "").startswith(SAST_PREFIX):
                matched.append(run)
                if len(matched) >= max_runs:
                    return matched
        if len(runs) < 100:
            break
    return matched


# ---------------------------------------------------------------------------
# Find the policy_scan job
# ---------------------------------------------------------------------------

def get_policy_scan_job(api_base: str, org: str, run_id: int, token: str) -> dict[str, Any]:
    """Find the policy_scan job in a run.

    Returns: {found: bool, job_conclusion: str}
    """
    r = gh_get(
        f"{api_base}/repos/{org}/{VERACODE_REPO}/actions/runs/{run_id}/jobs",
        token,
        params={"per_page": 100},
    )
    if r.status_code != 200:
        return {"found": False, "job_conclusion": ""}

    for job in r.json().get("jobs", []):
        job_name = (job.get("name") or "").lower().replace("-", "_").replace(" ", "_")
        if POLICY_JOB_NEEDLE in job_name:
            return {
                "found": True,
                "job_conclusion": job.get("conclusion") or "unknown",
            }

    return {"found": False, "job_conclusion": ""}


# ---------------------------------------------------------------------------
# Download only the policy_scan log from the zip
# ---------------------------------------------------------------------------

def download_policy_scan_log(api_base: str, org: str, run_id: int, token: str) -> str | None:
    """Download the log zip and extract the 'Veracode Upload and Scan Action Step'
    and 'Veracode Policy Results' content.

    GitHub log zips have two structures:
      1. A top-level file like 'policy_scan.txt' with just job conditional eval
         (tiny, ~300 bytes) - we want to SKIP this.
      2. A directory like 'policy_scan/' containing per-step files like:
           - '1_Set up job.txt'
           - '5_Veracode Upload and Scan Action Step.txt'
           - '6_Veracode Policy Results.txt'
         OR a single concatenated file with all step content.

    Strategy: search ALL files in the zip for content containing the two
    action references. Combine all matching content.
    """
    r = gh_get(f"{api_base}/repos/{org}/{VERACODE_REPO}/actions/runs/{run_id}/logs", token)
    if r.status_code != 200:
        return None

    UPLOAD_SCAN = "veracode/uploadandscan-action"
    INTEGRATION = "veracode/github-actions-integration-helper"

    upload_scan_content = ""
    integration_content = ""

    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size == 0:
                    continue
                # Skip files that aren't in/about the policy_scan job
                name_lower = info.filename.lower()
                if "policy_scan" not in name_lower and "policy scan" not in name_lower:
                    continue
                # Skip the tiny conditional-eval file
                if info.file_size < 1000:
                    continue

                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                except Exception:
                    continue

                # Per-step files: each file IS one step's log
                if UPLOAD_SCAN in content and "##[group]Run " + UPLOAD_SCAN in content:
                    section = _extract_section(content, UPLOAD_SCAN)
                    if section:
                        upload_scan_content = section

                if INTEGRATION in content and "##[group]Run " + INTEGRATION in content:
                    section = _extract_section(content, INTEGRATION)
                    if section:
                        integration_content = section

                # File named after the step directly (e.g. "5_Veracode Upload and Scan Action Step.txt")
                if "upload and scan" in name_lower or "upload_and_scan" in name_lower:
                    if not upload_scan_content:
                        upload_scan_content = content
                if "policy results" in name_lower or "policy_results" in name_lower:
                    if not integration_content:
                        integration_content = content
    except zipfile.BadZipFile:
        return None

    parts: list[str] = []
    if upload_scan_content:
        parts.append("=== Veracode Upload and Scan Action Step ===\n" + upload_scan_content)
    if integration_content:
        parts.append("=== Veracode Policy Results ===\n" + integration_content)

    return "\n\n".join(parts) if parts else None


def _extract_section(content: str, action_name: str) -> str:
    """From a multi-step concatenated log, extract just the section for one action.
    A section starts with '##[group]Run <action_name>' and ends at the next
    '##[group]Run' line or end of content.
    """
    section: list[str] = []
    capturing = False
    for line in content.splitlines():
        if "##[group]Run " in line:
            if capturing:
                break  # next section starts, we're done
            if action_name in line:
                capturing = True
                section.append(line)
                continue
        if capturing:
            section.append(line)
    return "\n".join(section)


# ---------------------------------------------------------------------------
# Parse the policy_scan log
# ---------------------------------------------------------------------------

_TS_GH = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+")
_TS_WRAPPER = re.compile(r"^\[\d{4}\.\d{2}\.\d{2}\s[\d:.]+\]\s*")


def _strip_timestamp(line: str) -> str:
    text = _TS_GH.sub("", line.strip())
    return _TS_WRAPPER.sub("", text)


def parse_policy_scan_log(log_text: str) -> dict[str, Any]:
    """Parse the policy_scan log for errors from uploadandscan-action
    and github-actions-integration-helper.

    Returns:
      findings_count: int (>0 = scan worked, skip this run)
      errors: list[str]
      error_types: list[str]
      veracode_app: str
    """
    error_types: set[str] = set()
    errors: list[str] = []
    findings_count = 0
    veracode_app = ""

    for raw_line in log_text.splitlines():
        text = _strip_timestamp(raw_line)
        if not text:
            continue

        # --- Findings count (>0 means scan completed, we skip these runs) ---

        if "Policy findings:" in text:
            try:
                findings_count = int(text.split("Policy findings:")[-1].strip())
            except ValueError:
                pass
            continue

        if "findings found" in text.lower() and text[0:1].isdigit():
            try:
                findings_count = int(text.split()[0])
            except (ValueError, IndexError):
                pass
            continue

        # --- Metadata ---

        if "Running a Policy Scan:" in text:
            veracode_app = text.split("Running a Policy Scan:")[-1].strip()
            continue

        # --- Errors from uploadandscan-action ---

        if "App not in state where new builds are allowed" in text:
            errors.append("App not in state where new builds are allowed")
            error_types.add("app_not_ready")

        elif "most recent scan has not finished" in text.lower():
            errors.append("Incomplete scan blocking new scan")
            error_types.add("scan_incomplete")

        elif "Attempting to delete the incomplete scan" in text:
            errors.append("Had to delete incomplete scan")
            error_types.add("scan_incomplete")

        elif "UploadAndScanByAppId" in text and "returned the following message" in text:
            errors.append(text[:200])
            error_types.add("upload_scan_error")

        # --- Errors from integration-helper ---

        elif "Bad credentials" in text:
            errors.append("Bad credentials (401)")
            error_types.add("bad_credentials")

        elif "RequestError" in text and "HttpError" in text:
            errors.append(text[:200])
            error_types.add("http_error")

        elif "TypeError:" in text:
            errors.append(text[:200])
            error_types.add("integration_bug")

        # --- HTTP status codes ---

        elif "status: 401" in text:
            error_types.add("http_401")
        elif "status: 400" in text:
            error_types.add("http_400")
        elif "status: 403" in text:
            error_types.add("http_403")

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for e in errors:
        if e not in seen:
            seen.add(e)
            unique.append(e)

    return {
        "findings_count": findings_count,
        "errors": unique,
        "error_types": sorted(error_types),
        "veracode_app": veracode_app,
    }


# ---------------------------------------------------------------------------
# Per-org audit
# ---------------------------------------------------------------------------

def audit_org(
    api_base: str, org: str, token: str, max_runs: int, logs_dir: Path,
) -> list[dict[str, Any]]:
    """Audit one org. Returns list of broken policy_scan run dicts.

    API calls per run:
      1. get jobs          (skip if policy_scan not found / success / skipped)
      2. download log zip  (only if policy_scan failed)
      3. parse log locally (skip if findings_count > 0)
    """
    results: list[dict[str, Any]] = []

    runs = fetch_sast_runs(api_base, org, token, max_runs)
    if not runs:
        _tprint(f"  [{org}] No SAST runs")
        return results

    _tprint(f"  [{org}] {len(runs)} SAST runs")

    for run in runs:
        run_id = run.get("id", 0)
        run_name = run.get("name") or ""
        target_repo = run_name[len(SAST_PREFIX):] if run_name.startswith(SAST_PREFIX) else ""
        run_conclusion = run.get("conclusion") or ""

        # Optimization: if the entire workflow run succeeded, the policy_scan
        # job either succeeded or was skipped. Either way, no error to investigate.
        # Skip without making the jobs API call.
        if run_conclusion == "success":
            continue

        # Check policy_scan job (1 API call)
        ps = get_policy_scan_job(api_base, org, run_id, token)
        if not ps["found"] or ps["job_conclusion"] in ("success", "skipped"):
            continue

        # Download policy_scan log only (1 API call)
        log_text = download_policy_scan_log(api_base, org, run_id, token)
        if not log_text:
            continue

        # Parse (0 API calls)
        parsed = parse_policy_scan_log(log_text)

        # Skip if findings were produced. Findings means the scan made it to
        # the Veracode platform and ran successfully. We only care about runs
        # that failed BEFORE producing findings.
        if parsed["findings_count"] > 0:
            continue

        # Skip if no actionable errors were detected in the two steps.
        if not parsed["error_types"]:
            continue

        # Broken: save log and record
        safe_repo = re.sub(r'[^\w\-.]', '_', target_repo)
        org_dir = logs_dir / org
        org_dir.mkdir(parents=True, exist_ok=True)
        log_path = org_dir / f"{safe_repo}_{run_id}.log"
        log_path.write_text(log_text, encoding="utf-8")

        entry: dict[str, Any] = {
            "org": org,
            "target_repo": target_repo,
            "run_id": run_id,
            "run_conclusion": run.get("conclusion") or "",
            "run_url": run.get("html_url") or "",
            "created_at": run.get("created_at") or "",
            "error_types": ", ".join(parsed["error_types"]),
            "errors": " | ".join(parsed["errors"]),
            "veracode_app": parsed["veracode_app"],
            "log_file": str(log_path),
        }

        label = parsed["error_types"] if parsed["error_types"] else ["unknown"]
        msg = parsed["errors"][0][:80] if parsed["errors"] else "no parsed errors"
        _tprint(f"  [{org}] {target_repo}: {label} - {msg}")
        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "org", "target_repo", "run_id", "run_conclusion",
    "error_types", "errors", "veracode_app",
    "run_url", "created_at", "log_file",
]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Find broken Veracode SAST policy_scan runs (zero findings, actual errors)."
    )
    ap.add_argument("--enterprise", help="GitHub Enterprise slug.")
    ap.add_argument("--orgs-file", help="File with org logins, one per line.")
    ap.add_argument("--out", default="out_audit", help="Output directory.")
    ap.add_argument("--api-base", default=_env("GITHUB_API_BASE", "https://api.github.com"))
    ap.add_argument("--token-env", default="GITHUB_TOKEN")
    ap.add_argument("--max-runs", type=int, default=20, help="SAST runs per org (default 20).")
    ap.add_argument("--workers", type=int, default=1, help="Parallel worker threads (default 1).")
    ap.add_argument("--skip-to", help="Skip orgs before this one.")
    ap.add_argument("--limit", type=int, default=0, help="Process only first N orgs.")
    args = ap.parse_args()

    token = _env(args.token_env)
    if not token:
        raise SystemExit(f"Set {args.token_env} env var")

    api_base = args.api_base.rstrip("/")

    # Token check
    print("[VALIDATION] Checking token...")
    r = gh_get(f"{api_base}/user", token)
    if r.status_code != 200:
        raise SystemExit(f"Token invalid: {r.status_code}")
    print(f"  OK: {r.json().get('login', '?')}")

    # Discover orgs
    orgs = discover_orgs(api_base, token, args.enterprise, args.orgs_file)

    if args.skip_to and args.skip_to in orgs:
        orgs = orgs[orgs.index(args.skip_to):]
        print(f"[SKIP] Starting from {args.skip_to}")

    if args.limit > 0:
        orgs = orgs[:args.limit]
        print(f"[LIMIT] {args.limit} orgs")

    # Output setup
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logs_dir = outdir / f"logs_{ts}"
    logs_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nAuditing {len(orgs)} orgs, {args.max_runs} SAST runs each, {args.workers} workers\n")

    # Incremental output: write each org's results to a JSONL file as we go
    # so a crash or KeyboardInterrupt doesn't lose all progress.
    jsonl_path = outdir / f"policy_scan_audit_{ts}.jsonl"
    jsonl_lock = threading.Lock()
    all_results: list[dict[str, Any]] = []

    def process_org(idx: int, org: str) -> list[dict[str, Any]]:
        _tprint(f"[{idx}/{len(orgs)}] {org}")
        try:
            results = audit_org(api_base, org, token, args.max_runs, logs_dir)
        except Exception as exc:
            _tprint(f"  [{org}] ERROR: {exc}")
            return []
        # Write incrementally
        if results:
            with jsonl_lock:
                with jsonl_path.open("a", encoding="utf-8") as f:
                    for entry in results:
                        f.write(json.dumps(entry) + "\n")
        return results

    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(process_org, i, org): org
                for i, org in enumerate(orgs, 1)
            }
            for future in as_completed(futures):
                all_results.extend(future.result())
    else:
        for i, org in enumerate(orgs, 1):
            all_results.extend(process_org(i, org))

    # Write CSV
    csv_path = outdir / f"policy_scan_audit_{ts}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(CSV_HEADER)
        for entry in all_results:
            w.writerow([entry.get(col, "") for col in CSV_HEADER])

    # Write JSON
    json_path = outdir / f"policy_scan_audit_{ts}.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    # Summary
    total = len(all_results)
    by_type: dict[str, int] = {}
    for entry in all_results:
        for t in entry.get("error_types", "").split(", "):
            if t:
                by_type[t] = by_type.get(t, 0) + 1

    print(f"\n{'=' * 50}")
    print(f"Broken policy_scan runs : {total}")
    print(f"Logs saved              : {sum(1 for e in all_results if e.get('log_file'))}")
    if by_type:
        print("By error type:")
        for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            print(f"  {t}: {c}")
    print(f"{'=' * 50}")
    print(f"\nCSV:  {csv_path}")
    print(f"JSON: {json_path}")
    print(f"Logs: {logs_dir}")


if __name__ == "__main__":
    main()
