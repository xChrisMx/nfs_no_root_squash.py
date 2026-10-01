# nfs_no_root_squash.py

Subnet-wide NFS export discovery and `no_root_squash` / anonymous-access
audit, rewritten onto the same house conventions as `telnet_spray.py` /
`ssh_vuln_scan.py` / `quantum_readiness_spray.py` / `sslspray.py`: masscan
discovery, a worker pool for assessment, the same live progress bar /
logging conventions, CWE-1236 hardening, two-stage Ctrl+C handling, and
`--from-csv`. Single Python file — scan, parse, CSV, and `.xlsx` are all in
it. Rewritten from the original `nfs_no_root_squash_v3.py` (left untouched
at the Cowork root; this is the new home for the tool going forward).

## What it finds

For every NFS export (or enumeration-incomplete placeholder row) found, one
of five categories, checked in this exact priority order (top to bottom,
first match wins):

1. 🔴 **Critical - Confirmed Root Escape (no_root_squash)** — NetExec
   (`nxc nfs <ip>`) CONFIRMED `root_escape=True`. Wins regardless of every
   other signal, including an otherwise-failed enumeration.
2. ⚪ **Unknown - Enumeration Incomplete** — `showmount` failed, or
   succeeded with no parseable exports, and root_escape isn't a confirmed
   TRUE. Checked before the scope/likelihood checks below, since those
   aren't meaningful without a successfully-enumerated export.
3. 🟠 **High - Broad Export, Anonymous Access Likely** — root_escape is
   UNKNOWN or a confirmed FALSE, but the INFERRED `root_escape_likelihood`
   is VERY_HIGH or HIGH.
4. 🟡 **Medium - Broad Export, Limited Evidence** — INFERRED likelihood is
   MEDIUM, or root_escape is a confirmed FALSE but the export's
   `scope_risk` is still CRITICAL/HIGH (root is safe, but the export is
   still broadly reachable — a distinct, non-zero data-exposure concern).
5. 🟢 **Low - Scoped Export, Root Squash Enforced or Low Risk** — fallback:
   everything else that was successfully enumerated.

Display/legend order (Overview sheet, category table) is CRITICAL → HIGH →
MEDIUM → LOW → UNKNOWN — UNKNOWN last because it isn't a severity level,
it's a "couldn't tell" bucket, matching how `telnet_spray.py` orders its own
"Unknown / Silent" last for the same reason. This differs on purpose from
the priority-check order above (CRITICAL first, UNKNOWN **second**) — see
`classify_finding()`'s docstring in the script for the one genuinely
ambiguous case this ordering had to resolve.

## Why CONFIRMED vs INFERRED root_escape matters

This is the single most important thing to understand about this tool's
output. `root_escape` (TRUE/FALSE/UNKNOWN) and `root_escape_confidence`
(CONFIRMED/INFERRED) are two different columns for a reason:

- **CONFIRMED** — NetExec (`nxc`/`netexec`, optional dependency) actually
  ran `nxc nfs <ip>` against the host and it reported
  `root escape:True`/`False`. This is a real test result.
- **INFERRED** — `nxc`/`netexec` wasn't installed, or the per-host call
  failed/timed out. `root_escape` stays `UNKNOWN`, and the only signal left
  is `root_escape_likelihood` (VERY_HIGH/HIGH/MEDIUM/LOW/UNKNOWN) — a
  heuristic built purely from `showmount`'s allowed-client scope plus
  read-only nmap NSE enrichment (`nfs-ls`/`nfs-statfs`) suggesting anonymous
  access looks possible. That is **not** the same claim as "root squashing
  is disabled" — it's a guess, however well-informed.

A confirmed root escape (`root_escape == "TRUE"`) always lands in the
Critical bucket, no matter what else was or wasn't observed. Every other
bucket is explicitly built from inferred signals and labeled as such —
never silently presented as a confirmed verdict. If `nxc`/`netexec` isn't
installed, install it for definitive True/False verdicts; without it, this
tool can still flag broadly-exported, likely-anonymous-access hosts, but
cannot confirm root escape on any of them.

## Why two phases (and why the nmap fallback is kept here, unlike the masscan-only siblings)

The configured scope (`SUBNETS` below) includes a `/8`. **Phase 1**
(discovery) finds which hosts across all configured subnets have TCP/2049
open, so **Phase 2** (assessment) only has to touch real hosts.

Every sibling script (`telnet_spray.py`, `ssh_vuln_scan.py`,
`quantum_readiness_spray.py`, `sslspray.py`) requires masscan for Phase 1,
full stop. This script keeps a genuine feature from the original
`nfs_no_root_squash_v3.py` that none of the siblings have: **if masscan is
missing or fails, Phase 1 automatically falls back to a pure-nmap SYN/connect
scan** instead of refusing to run. This is deliberate, not an oversight —
NFS audits in this environment are frequently run from hosts/engagements
where masscan isn't installed or root/raw-socket privileges aren't available
(masscan needs both), and a pure-nmap path is the only discovery option left
in that case. The fallback's progress display uses the exact same
`draw_progress_line()`/`render_bar()` primitives as masscan's own progress
bar, so it reads identically to every other phase in this tool and its
siblings — only the underlying scanner and its percent/ETA parsing differ.

Phase 2 then runs, per host, concurrently: hostname resolution (reverse
DNS, with `dig`/`host` fallbacks — richer than the siblings' single
`socket.gethostbyaddr()` call, kept from the original script because it
measurably improves hit rate here), `showmount -e` export enumeration,
read-only nmap NSE scripts (`nfs-showmount`, `nfs-ls`, `nfs-statfs`) for
access-evidence inference, and `nxc nfs <ip>` for the confirmed verdict.

## Scope

```python
SUBNETS: List[str] = [
    "1.0.0.0/8",
    "2.0.0.0/12",
    "3.0.0.0/16",
    # "4.0.0.0/16",
    "5.0.0.0/16",
    "6.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/16",
    "9.0.0.0/16",
]
```

Edit this list in the script to change scope — same convention as the
sibling scripts.

## Requirements

- `nmap` — **required** (NSE enrichment step, and the discovery fallback)
- `showmount` (nfs-common / nfs-utils) — **required**
- `masscan` — optional; much faster Phase 1 discovery on large ranges, needs
  root/raw sockets. Falls back to nmap automatically if missing or if it fails.
- `nxc` / `netexec` — optional; without it, `root_escape` stays `UNKNOWN`
  for every host and the root-escape-only CSV is empty (see "Why CONFIRMED
  vs INFERRED" above).
- `dig` / `host` — optional; improve hostname resolution beyond Python's
  own `socket.gethostbyaddr`/`getfqdn`. Failures resolve to a blank hostname.
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to
  CSV-only instead of failing.

```bash
pip install openpyxl
```

None of the above are required for `--help` or `--from-csv` — tool checks
happen inside `main()`, not at import time, specifically so a report can be
rebuilt from existing data with zero external tools present.

## Usage

```bash
sudo python nfs_no_root_squash.py
```

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `64` | Concurrent per-host workers in Phase 2 |
| `--masscan-rate` | `25000` | masscan packets/sec |
| `--masscan-retries` | `1` | masscan `--retries` (extra retransmits per host) |
| `--nmap-timing` | `T4` | nmap timing template (discovery fallback + NSE step), no leading `-` |
| `--nmap-min-rate` | `1000` | nmap fallback `--min-rate` packets/sec floor |
| `--showmount-timeout` | `6` | Per-host `showmount -e` timeout, seconds |
| `--nse-timeout` | `25` | Per-host nmap NSE script timeout, seconds |
| `--nxc-timeout` | `30` | Per-host `nxc nfs` timeout, seconds |
| `--retries` | `1` | Retries per showmount/NSE/nxc call on a timeout/connection-style failure only (not retried for a clean, deterministic non-match — see Architecture notes) |
| `--output-dir` | script's own directory | Where the log/CSVs/xlsx are written |
| `--masscan-path` | `masscan` | Path/name of the masscan binary |
| `--nmap-path` | `nmap` | Path/name of the nmap binary |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |
| `--prefer-nmap` | off | Force nmap-only discovery even if masscan is on PATH (restores the old script's `PREFER_MASSCAN=False` option — e.g. an engagement where only nmap connect/SYN scanning is authorized) |
| `--no-xlsx` | off | Stop after the CSVs |
| `--from-csv FILE` | — | Skip scanning entirely (zero external tool calls); rebuild the `.xlsx` from a previously-written detail CSV |

Reuse a previous masscan run:

```bash
python nfs_no_root_squash.py --skip-masscan --masscan-output-file .masscan_output_09_2026.txt
```

Rebuild just the `.xlsx` from an existing detail CSV without re-scanning
(works with none of nmap/showmount/masscan/nxc installed):

```bash
python nfs_no_root_squash.py --from-csv nfs_exports_detail_09_2026.csv
```

## Output

Everything is written to `--output-dir`, with a monthly (`MM_YYYY`) date
suffix — the same filename convention the original script already used
(unlike the siblings' daily suffix), kept because these reports are
typically reviewed/aggregated on a monthly cadence:

- `nfs_no_root_squash_<MM_YYYY>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `nfs_exports_detail_<MM_YYYY>.csv` — one row per export (plus one placeholder row per host whose exports couldn't be enumerated)
- `nfs_hosts_summary_<MM_YYYY>.csv` — one row per host, aggregated from the detail rows
- `nfs_root_escape_TRUE_<MM_YYYY>.csv` — remediation-only list: hosts with a CONFIRMED root escape
- `nfs_no_root_squash_<MM_YYYY>.xlsx` — **Overview** + **Scan Results** sheets
- `.masscan_output_<MM_YYYY>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `nfs_exports_detail_<MM_YYYY>.csv`

```
subnet,server_ip,hostname,dns_note,export_path,allowed_clients,scope_risk,listing_access,statfs_access,root_escape,nfs_versions,root_escape_confidence,root_escape_evidence,root_escape_likelihood,root_escape_basis,verification_required,risk_reason,why_flagged,note
```

### `nfs_hosts_summary_<MM_YYYY>.csv`

```
subnet,server_ip,hostname,dns_note,exports_count,exports_sample,highest_scope_risk,root_escape,nfs_versions,root_escape_confidence,root_escape_evidence,highest_root_escape_likelihood,verification_required,risk_reason,why_flagged,showmount_status,nse_status,nxc_status
```

### `nfs_root_escape_TRUE_<MM_YYYY>.csv`

```
subnet,server_ip,hostname,root_escape,nfs_versions,root_escape_confidence,root_escape_evidence,highest_scope_risk,exports_count,exports_sample,why_flagged
```

### `nfs_no_root_squash_<MM_YYYY>.xlsx`

**Overview** — title/scan metadata (including whether NetExec was available
at scan time), a "How to read this report" explainer centered on the
CONFIRMED-vs-INFERRED distinction, the 5-category table (emoji/fill/
description), methodology notes (the 4 bullets covering Phase 1/2, the
CONFIRMED-vs-INFERRED rule explicitly, the port-open-vs-real-NFS caveat, and
the non-destructive guarantee), a scan summary (host count, export-row
count, confirmed-root-escape host count, per-category counts + %), and a
subnet breakdown (by export row).

**Scan Results** — one row per export (same grain as the detail CSV), plus
a `category` column — frozen header, autofilter, every row colored by its
`classify_finding()` category, `export_path`/`allowed_clients`/
`risk_reason`/`why_flagged`/`root_escape_evidence` wrap-text enabled.

## What it checks, and how it's classified

See "What it finds" above for the full 5-bucket table and priority order.
Per-export scoring itself (`scope_risk`, `root_escape_likelihood_for_export`,
`risk_reason_and_why`) is unchanged from the original script — only the
category bucketing (`classify_finding()`) and the report formats around it
are new.

## Architecture notes

**Phase 1** is masscan-preferred, nmap-fallback (see "Why two phases"
above). Masscan's progress parsing (`MasscanStatus`, `_masscan_stderr_reader`)
is ported near-verbatim from the sibling scripts. The nmap fallback
(`NmapDiscoveryStatus`, `_nmap_stdout_reader`, `run_nmap_discovery_phase1()`)
parses the same `--stats-every` percent/ETA text the original script's
bespoke `_parse_scan_percent()` did, just routed through the shared
`draw_progress_line()`/`render_bar()` primitives instead.

**Phase 2** (`scan_one_host()` / `_scan_one_host_inner()`) shells out to
**three** subprocesses per host — `showmount`, `nmap --script nfs-*`, and
`nxc nfs` — closer to `ssh_vuln_scan.py`'s per-host nmap-worker-pool
pattern than `telnet_spray.py`'s single-raw-socket-probe model. Each
subprocess call goes through `_run_cmd_with_retry()`.

**Retry logic**: `_is_retryable(rc, out)` only retries `rc == 124` (our
`run_cmd()`'s own timeout marker) or an `rc != 0` result whose output starts
with `"[error]"` (meaning `run_cmd()` caught an exception launching/talking
to the subprocess — a connection-style failure). A clean, non-zero rc with
real stdout (e.g. showmount's own `clnt_create: RPC: Program not
registered` rejection) is a deterministic property of the host, not a
transient miss, and is **not** retried — same "only retry a transient
failure" rule the sibling scripts use for their own retry loops.

**One bad host can't take down the batch** — `scan_one_host()` wraps
`_scan_one_host_inner()` in a broad except, same per-host exception
guarding as `ssh_vuln_scan.py`'s `scan_one_host()`.

**`classify_finding()` is a pure function** of `(root_escape,
root_escape_likelihood, scope_risk, showmount_ok, exports_present)` — it's
called identically whether building a row during a live scan
(`build_rows_for_host()`) or recomputing a row's category after a
`--from-csv` reload (`category_for_row()`, which derives `showmount_ok`/
`exports_present` from the row's own `note` field). There is exactly one
place this logic lives, so a live scan and a `--from-csv` rebuild of its
own output always agree on every row's category.

## Security notes

**CSV/Excel formula injection (CWE-1236) is now neutralized — the prior
version of this script (`nfs_no_root_squash_v3.py`) had NO sanitization or
formula-injection hardening at all.** `hostname`, `export_path`,
`allowed_clients`, `risk_reason`, `why_flagged`, `root_escape_evidence`, and
`nfs_versions` are all sourced from (or built from) whatever the scanned
NFS server, its reverse-DNS PTR record, or NetExec's own output presents —
attacker-influenceable by design, since that's exactly what this tool
audits. `_neutralize_formula()` (ported verbatim from `telnet_spray.py`)
prefixes a single quote onto any such value starting with `=`, `+`, `-`,
`@`, tab, or CR before it reaches `csv.writer` or an openpyxl cell, in
`write_detail_csv()`, `write_summary_csv()`, `write_rootescape_csv()`, and
`build_workbook()` alike.

**A malicious or malformed export path/hostname/nxc response can't crash
`.xlsx` generation.** `_sanitize_text()` (also ported verbatim) strips
characters illegal in XML 1.0 — the same category that crashes openpyxl
with `IllegalCharacterError` — and caps every field at 2000 characters,
applied in `build_rows_for_host()` at capture time and again in
`read_rows_from_csv()` for the `--from-csv` path, so a hand-edited or
externally-produced CSV can't reach openpyxl with an illegal character
either.

**`require_tool()`'s module-level `sys.exit(1)` calls are gone.** The
prior version resolved `NMAP`/`SHOWMOUNT` as module-level constants via
`require_tool()`, so even `--help` (or merely importing the module) failed
hard if nmap/showmount weren't installed. Tool checks now happen inside
`main()`, log a clear error, and `return 1` — and are skipped entirely on
the `--from-csv` path, so a report can be rebuilt with zero external tools
present.

## Limitations

**A masscan/nmap hit on TCP/2049 only proves the port is open**, not that
real NFS is behind it. A failed `showmount` is the main signal this tool
uses to tell "NFS wasn't actually listening" apart from "a genuine empty
export list" — both land in `Unknown - Enumeration Incomplete` for a human
to check directly.

**`nxc nfs <ip>`'s "root escape:True/False" verdict is trusted as correct.**
This script treats NetExec as an external, trusted oracle for that specific
claim and has not independently re-derived or verified NetExec's internal
NFS module logic beyond what its own output documents. If NetExec's
behavior here ever needs independent verification, that's a NetExec-level
question, not something this script re-implements.

**Reverse DNS depends on corporate DNS/`dig`/`host` availability**;
failures resolve to a blank hostname and do not stop the scan.

**masscan/nmap SYN discovery need root/raw sockets** — run with `sudo` /
as Administrator.

**EOL/compliance judgment calls on individual findings still need a
human** — this tool flags and scores, it does not adjudicate a ticket.

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits with code 130. Same as the
sibling scripts.
