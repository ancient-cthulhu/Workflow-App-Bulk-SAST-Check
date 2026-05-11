# Veracode Bulk SAST Policy Scan Check

Checks the Veracode Static Code Analysis workflows across GitHub Enterprise organizations to find broken `policy_scan` runs that need bulk remediation. Pulls workflow runs from each org’s `veracode` repository, identifies runs where the policy scan failed before producing findings, parses the step logs for actionable errors, and produces a CSV of every broken run with the error category and direct run URL.

-----

## How It Works

For each organization, the script:

1. Lists the last N `Static Code Analysis - <repo>` runs from `{org}/veracode`
1. Inspects each run’s `policy_scan` job conclusion
1. For failed jobs, downloads the log zip and extracts only the two relevant step sections:
- `Veracode Upload and Scan Action Step` (uses `veracode/uploadandscan-action`)
- `Veracode Policy Results` (uses `veracode/github-actions-integration-helper`)
1. Parses those sections for actionable error categories
1. Discards any run that produced findings (findings means the scan reached the Veracode platform and ran successfully - those are policy results, not infrastructure failures)
1. Saves the extracted log content and writes one CSV row per truly broken run

Runs are skipped without further work in these cases:

- Workflow run conclusion is `success` (no API call to inspect jobs)
- `policy_scan` job conclusion is `success` or `skipped` (the `if` condition was false and the job never ran)
- The parsed log shows `findings_count > 0` (scan worked, this is just a policy violation)
- No actionable error categories were detected in the two step sections

-----

## Quickstart

```bash
export GITHUB_TOKEN="..."

# Audit a single enterprise
python script.py --enterprise YOUR-ENTERPRISE

# Audit a specific list of orgs
python script.py --orgs-file orgs.txt --max-runs 100

# Parallel run for large enterprises
python script.py --enterprise YOUR-ENTERPRISE --max-runs 100 --workers 4
```

Output is written to `./out_audit/`:

- `policy_scan_audit_<timestamp>.csv` - one row per broken run
- `policy_scan_audit_<timestamp>.json` - same data as JSON
- `policy_scan_audit_<timestamp>.jsonl` - incremental write, one line per broken run (crash-safe)
- `logs_<timestamp>/<org>/<repo>_<run_id>.log` - extracted step content for each broken run

-----

## Requirements

```bash
pip install requests
```

Python 3.10+

-----

## GitHub Token Permissions

|Operation                         |Required Scopes                                         |
|----------------------------------|--------------------------------------------------------|
|Read workflow runs and logs       |`repo` (or `public_repo` if all target repos are public)|
|`--enterprise` (org discovery)    |`read:enterprise`                                       |
|Org list via `/user/orgs` fallback|`read:org`                                              |

Full audit: `repo`, `read:org`, `read:enterprise`

-----

## Command-Line Reference

### Scope

|Flag               |Description                                                      |
|-------------------|-----------------------------------------------------------------|
|`--enterprise SLUG`|GitHub Enterprise slug for org discovery via GraphQL             |
|`--orgs-file FILE` |Plain text file with one org login per line. `#` for comments.   |
|`--skip-to ORG`    |Skip all orgs before this one (useful for resuming after a crash)|
|`--limit N`        |Process only the first N orgs                                    |

If neither `--enterprise` nor `--orgs-file` is provided, the script falls back to `/user/orgs` (all orgs accessible to the token).

### Configuration

|Flag             |Default                 |Description                                                            |
|-----------------|------------------------|-----------------------------------------------------------------------|
|`--max-runs N`   |`20`                    |Number of latest SAST runs to inspect per org                          |
|`--workers N`    |`1`                     |Parallel worker threads. See [Parallel Execution](#parallel-execution).|
|`--out DIR`      |`./out_audit`           |Output directory                                                       |
|`--api-base URL` |`https://api.github.com`|Override for GHES                                                      |
|`--token-env VAR`|`GITHUB_TOKEN`          |Environment variable holding the GitHub token                          |

-----

## Error Categories

The script classifies each broken run into one or more of the following categories based on the parsed log content:

|Category                            |Source step    |Meaning                                                                                                            |
|------------------------------------|---------------|-------------------------------------------------------------------------------------------------------------------|
|`app_not_ready`                     |Upload and Scan|“App not in state where new builds are allowed” - profile is locked by another in-progress scan                    |
|`scan_incomplete`                   |Upload and Scan|“The most recent scan has not finished” - previous scan never completed cleanly                                    |
|`upload_scan_error`                 |Upload and Scan|`UploadAndScanByAppId` returned a non-empty error message                                                          |
|`bad_credentials`                   |Policy Results |`RequestError [HttpError]: Bad credentials` - the GitHub token used by the integration helper is invalid or expired|
|`http_401` / `http_400` / `http_403`|Either         |HTTP status returned by the Veracode or GitHub API                                                                 |
|`http_error`                        |Policy Results |Generic `RequestError [HttpError]` not matching a specific status                                                  |
|`integration_bug`                   |Policy Results |JavaScript `TypeError` thrown by the integration helper action                                                     |

Multiple categories may apply to a single run (e.g. `bad_credentials, http_401`). All categories are recorded in the `error_types` column.

-----

## Output Files

### CSV (`policy_scan_audit_<timestamp>.csv`)

|Column          |Description                                                        |
|----------------|-------------------------------------------------------------------|
|`org`           |Organization login                                                 |
|`target_repo`   |Repository scanned (parsed from the workflow run name)             |
|`run_id`        |GitHub Actions run ID                                              |
|`run_conclusion`|Top-level workflow run conclusion (`failure`, `cancelled`, etc.)   |
|`error_types`   |Comma-separated list of error categories detected                  |
|`errors`        |Pipe-separated list of the actual error messages from the log      |
|`veracode_app`  |Veracode application profile name (from “Running a Policy Scan: …”)|
|`run_url`       |Direct link to the workflow run in GitHub                          |
|`created_at`    |When the run started                                               |
|`log_file`      |Path to the extracted step content for this run                    |

### Log files (`logs_<timestamp>/<org>/<repo>_<run_id>.log`)

Each file contains only the two relevant step sections, not the full job log. A typical file is 15-30 KB and starts with:

```
##[group]Run veracode/uploadandscan-action@v0.2.0
...
##[group]Run veracode/github-actions-integration-helper@v0.1.9
...
```

This is the minimum content needed to diagnose the failure, with no noise from setup, checkout, or post-job cleanup steps.

-----

## Parallel Execution

By default the script processes one org at a time. Use `--workers N` to process multiple orgs concurrently using a thread pool. All API calls are I/O-bound, so threading provides real throughput gains.

```bash
# Audit 200 orgs with 100 runs each, using 4 parallel workers
python script.py --enterprise YOUR-ENTERPRISE --max-runs 100 --workers 4
```

### Choosing a worker count

|Workers|Use case                                                      |
|-------|--------------------------------------------------------------|
|`1`    |Default. Sequential. Easiest to read logs.                    |
|`3`    |Safe starting point for most Checks.                          |
|`5`    |Recommended for large enterprises (100+ orgs, 100+ runs each).|
|`10`   |Maximum recommended. Approaches rate limit risk at peak.      |

### Rate limit behavior

GitHub’s authenticated API rate limit is 5,000 requests per hour per token. All workers share a single global rate limit state. When any worker receives a near-limit signal (`X-RateLimit-Remaining < 50`), it sets a shared resume timestamp and all other workers pause until the window resets. This prevents mass restarts and 429 storms.

### API call budget

Per org, in the worst case (every run failed):

|Step                                              |API calls                    |
|--------------------------------------------------|-----------------------------|
|List workflow runs                                |1-5 (paginated, 100 per page)|
|Get jobs for each failed run                      |1 per non-success run        |
|Download log zip for each failed `policy_scan` job|1 per qualifying run         |

For a 200-org audit with 100 runs each and a 30% failure rate, expect roughly 9,000-12,000 API calls. Successful workflow runs are skipped without inspecting their jobs, which keeps the call budget bounded.

-----

## Crash Recovery

Results are written to a `.jsonl` file incrementally as each org completes, so a crash, `Ctrl+C`, or rate-limit hang does not lose previously processed orgs. To resume from where you left off, use `--skip-to ORG` with the next org in your list.

The final `.csv` and `.json` files are only written at the end of a successful run. If the script crashes, recover the partial data from the `.jsonl` file directly.

-----

## Platform Notes

### GitHub Enterprise Cloud (GHEC)

All features supported.

```bash
python script.py --enterprise your-enterprise-slug --max-runs 100 --workers 4
```

### GitHub Enterprise Server (GHES)

```bash
python script.py \
  --enterprise your-enterprise-slug \
  --api-base https://github.company.com/api/v3 \
  --max-runs 100 --workers 4
```

-----

## Support

Supported platforms: GitHub.com, GitHub Enterprise Cloud, GitHub Enterprise Server

For issues, provide `out_audit/policy_scan_audit_<timestamp>.csv` and a sample log file from `out_audit/logs_<timestamp>/`.

> This is a community tool and is not officially supported by Veracode.
