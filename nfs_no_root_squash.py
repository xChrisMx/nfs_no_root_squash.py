#!/usr/bin/env python3
# =============================================================================
# nfs_no_root_squash.py
#
# AUTHORIZED INTERNAL SECURITY ASSESSMENT TOOL
# Scope: NFS (TCP/2049) export discovery + no_root_squash / anonymous-access
#        audit on internal company networks. Rewritten from the original
#        nfs_no_root_squash_v3.py onto the same house conventions as
#        telnet_spray.py / ssh_vuln_scan.py / quantum_readiness_spray.py /
#        sslspray.py (progress bar + logging, masscan Phase 1 discovery,
#        category-bucket Overview sheet, CWE-1236 hardening, two-stage
#        SIGINT, argparse, --from-csv).
#
# -----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES
# -----------------------------------------------------------------------------
# Phase 1 (Discovery): Finds hosts with TCP/2049 open across the configured
#   subnets. Masscan-preferred, nmap-fallback (see DELIBERATE DEVIATION below).
#
# Phase 2 (Assessment): For every host discovered in Phase 1, a pool of
#   worker threads each run, per host:
#     1. Hostname resolution (reverse DNS, with dig/host fallbacks).
#     2. `showmount -e <ip>` -- enumerates the host's NFS exports and their
#        allowed-client strings.
#     3. Read-only nmap NSE scripts (nfs-showmount, nfs-ls, nfs-statfs) --
#        enrichment used to INFER whether anonymous directory listing/statfs
#        access looks possible.
#     4. `nxc nfs <ip>` (NetExec), if installed -- the one step that can
#        actually CONFIRM a root-escape (no_root_squash) verdict.
#   Phase 2 then scores each export's risk and writes ticket-ready text.
#
# -----------------------------------------------------------------------------
# THE SINGLE MOST IMPORTANT THING TO UNDERSTAND: root_escape IS EITHER
# CONFIRMED OR INFERRED, AND THE REPORT NEVER LETS YOU CONFUSE THE TWO
# -----------------------------------------------------------------------------
# `root_escape` (TRUE / FALSE / UNKNOWN) comes directly from NetExec's
# `nxc nfs <ip>` output ("root escape:True/False"). NetExec actually attempts
# the escape-relevant behavior against the server, so when it reports
# True/False, that is a CONFIRMED verdict -- root_escape_confidence=CONFIRMED.
#
# When `nxc`/`netexec` is not installed (or the per-host call fails/times
# out), root_escape is UNKNOWN and root_escape_confidence=INFERRED. In that
# case the ONLY signal this tool has is `root_escape_likelihood`
# (VERY_HIGH/HIGH/MEDIUM/LOW/UNKNOWN) -- a heuristic built purely from
# showmount's allowed-client scope plus the nfs-ls/nfs-statfs NSE enrichment,
# i.e. "does this export look broadly reachable AND does remote enumeration
# suggest anonymous access is possible", which is NOT the same claim as
# "root squashing is disabled". A VERY_HIGH likelihood is still a guess.
#
# Every output (detail CSV, summary CSV, the classify_finding() bucket, and
# the Overview sheet's methodology notes) keeps this distinction visually and
# textually explicit -- root_escape_confidence is its own column, never
# silently folded into root_escape_likelihood or vice versa. A confirmed
# root escape (root_escape=="TRUE") always lands in the Critical bucket
# regardless of every other signal; everything else is explicitly inferred.
#
# -----------------------------------------------------------------------------
# DELIBERATE DEVIATION FROM THE SIBLING SCRIPTS: NMAP-FALLBACK DISCOVERY
# -----------------------------------------------------------------------------
# Every sibling script (telnet_spray.py, ssh_vuln_scan.py,
# quantum_readiness_spray.py, sslspray.py) requires masscan for Phase 1, full
# stop. This script keeps the original nfs_no_root_squash_v3.py's nmap
# fallback instead of dropping it to match the siblings, because NFS audits
# in this environment are frequently run from hosts/engagements where
# masscan isn't installed or root/raw-socket privileges aren't available
# (masscan needs both), and a pure-nmap SYN/connect scan is the only
# discovery path left in that situation. This is a genuine, valuable
# capability the siblings don't have; it is kept on purpose, not an
# oversight, and the fallback's progress display now uses the exact same
# `draw_progress_line()`/`render_bar()` primitives as masscan's so it reads
# identically to every other phase in this tool and its siblings.
#
# -----------------------------------------------------------------------------
# NON-DESTRUCTIVE / SAFETY GUARANTEES
# -----------------------------------------------------------------------------
# `showmount -e` and the three NSE scripts (nfs-showmount, nfs-ls,
# nfs-statfs) only query/list what the server already advertises -- no
# export is ever mounted by this tool, and no file on any target export is
# read, written, or created. `nxc nfs <ip>` is NetExec's own built-in NFS
# enumeration module; this script treats it as a black box and does not
# independently verify its internal implementation. If you are not 100%
# certain what that module does under the hood beyond what its own output
# documents, say so honestly -- see LIMITATIONS below rather than asserting
# something unverified.
#
# THIS TOOL MUST ONLY BE RUN AGAINST NETWORKS YOU ARE EXPLICITLY AUTHORIZED
# TO ASSESS. Confirm written authorization / an active engagement scope
# before running this script.
#
# -----------------------------------------------------------------------------
# LIMITATIONS AND ASSUMPTIONS
# -----------------------------------------------------------------------------
#   - masscan (if used) and nmap SYN-style discovery need root/raw sockets.
#     Run with sudo / as an account with that privilege.
#   - `nxc`/`netexec`, `dig`, and `host` are all optional and degrade
#     gracefully: without `nxc`, root_escape stays UNKNOWN for every host and
#     the remediation-only CSV will be empty; without `dig`/`host`, hostname
#     resolution falls back to Python's own socket.gethostbyaddr/getfqdn and
#     ultimately to a blank hostname if none of the four resolution paths
#     succeed.
#   - A masscan/nmap hit on TCP/2049 only proves the port is open, not that
#     real NFS is behind it -- a failed `showmount` is the main signal this
#     tool uses to distinguish "NFS wasn't actually listening" / "blocked
#     upstream" from a genuine empty export list, and both land in the
#     UNKNOWN bucket for a human to check directly.
#   - Reverse-DNS resolution depends on corporate DNS/`dig`/`host`
#     availability; failures resolve to a blank hostname and do not stop the
#     scan.
#   - `nxc nfs <ip>`'s "root escape:True/False" line is trusted as a
#     correct confirmation/denial of no_root_squash because that is what
#     NetExec's own documentation and output claim it tests -- this script
#     has not independently re-derived or verified NetExec's internal NFS
#     module logic, and treats it as an external, trusted oracle rather than
#     re-implementing the check itself.
#   - EOL/compliance judgment calls on individual findings still need a
#     human -- this tool flags and scores, it does not adjudicate a ticket.
# =============================================================================

import argparse
import csv
import ipaddress
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Same subnets in scope as the sibling sweep tools. Edit this list to change
# scope.
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

NFS_PORT = 2049

DEFAULT_WORKERS = 64              # concurrent per-host workers; lower (16-24) is gentler on target hosts
DEFAULT_MASSCAN_RATE = 25000      # packets/sec for masscan; higher = faster but noisier
DEFAULT_MASSCAN_RETRIES = 1       # extra retransmits per host; 0 is fastest but can miss hosts on lossy links
DEFAULT_NMAP_TIMING = "T4"        # nmap fallback timing; T4 is appropriate for trusted internal networks
DEFAULT_NMAP_MIN_RATE = 1000      # packets/sec floor for nmap fallback
DEFAULT_NMAP_STATS_EVERY = "15s"  # how often nmap fallback prints progress/ETA (nmap --stats-every)
DEFAULT_SHOWMOUNT_TIMEOUT = 6
DEFAULT_NSE_TIMEOUT = 25
DEFAULT_NXC_TIMEOUT = 30
DEFAULT_DNS_TIMEOUT = 2.0         # per DNS-resolution attempt (ptr/fqdn/dig/host), not exposed via CLI
DEFAULT_RETRIES = 1               # bounded retry of showmount/NSE/nxc on a timeout/connection-style failure only

NSE_SCRIPTS = "nfs-showmount,nfs-ls,nfs-statfs"

# -----------------------------------------------------------------------------
# Finding category buckets (classify_finding() below)
# -----------------------------------------------------------------------------
NFS_CRITICAL = "Critical - Confirmed Root Escape (no_root_squash)"
NFS_UNKNOWN = "Unknown - Enumeration Incomplete"
NFS_HIGH = "High - Broad Export, Anonymous Access Likely"
NFS_MEDIUM = "Medium - Broad Export, Limited Evidence"
NFS_LOW = "Low - Scoped Export, Root Squash Enforced or Low Risk"

# Overview table / legend display order: severity descending, then UNKNOWN
# last since it isn't a severity level at all -- it's a "couldn't tell"
# bucket, matching how telnet_spray.py orders its own "Unknown / Silent"
# last in AUTH_ORDER for the same reason. NOTE this differs from the
# priority-check order in classify_finding() (CRITICAL first, UNKNOWN
# SECOND) -- see classify_finding()'s own docstring for why the check order
# and the display order are allowed to differ.
NFS_ORDER = [NFS_CRITICAL, NFS_HIGH, NFS_MEDIUM, NFS_LOW, NFS_UNKNOWN]

NFS_EMOJI = {
    NFS_CRITICAL: "\U0001F534",   # red circle
    NFS_HIGH: "\U0001F7E0",       # orange circle
    NFS_MEDIUM: "\U0001F7E1",     # yellow circle
    NFS_LOW: "\U0001F7E2",        # green circle
    NFS_UNKNOWN: "⚪",             # white circle
}

NFS_FILL_HEX = {
    NFS_CRITICAL: "FFC7CE",
    NFS_UNKNOWN: "E7E6E6",
    NFS_HIGH: "FCE4D6",
    NFS_MEDIUM: "FFEB9C",
    NFS_LOW: "C6EFCE",
}

NFS_FONT_HEX = {
    NFS_CRITICAL: "922B21",
    NFS_UNKNOWN: "5D6D7E",
    NFS_HIGH: "784212",
    NFS_MEDIUM: "7D6608",
    NFS_LOW: "1E6B2E",
}

# Longer, paragraph-length text for the Overview sheet's category table.
NFS_DESCRIPTION = {
    NFS_CRITICAL: (
        "NetExec (`nxc nfs <ip>`) CONFIRMED that this host hands out root escalation to "
        "any client (no_root_squash is in effect; root_escape=True). This wins over every "
        "other signal -- even if showmount enumeration failed or the remote scope looks "
        "narrow -- because a confirmed root escape is immediately exploitable for "
        "privilege escalation regardless of anything else observed. Remediate "
        "immediately: enable root_squash and restrict client scope."
    ),
    NFS_UNKNOWN: (
        "showmount could not enumerate this host's exports at all (connection failure, "
        "timeout, or empty output), or it returned exports that could not be parsed, and "
        "NetExec did NOT confirm a root escape here. There isn't enough remote evidence "
        "to judge export scope or access risk one way or the other -- this needs a human "
        "to check the server directly (export configuration, firewall rules blocking the "
        "mount protocol, or a non-standard NFS implementation)."
    ),
    NFS_HIGH: (
        "NetExec either wasn't available or didn't confirm a root escape, but the "
        "INFERRED root_escape_likelihood from export scope + NSE evidence is VERY_HIGH "
        "or HIGH -- the export looks broadly reachable (all-clients or a wide CIDR) and "
        "remote enumeration (nfs-ls/nfs-statfs) suggests anonymous listing/statfs access "
        "is actually possible. This is an INFERRED finding, not a confirmed one -- install "
        "and run NetExec against this host for a definitive True/False verdict."
    ),
    NFS_MEDIUM: (
        "Either the inferred root_escape_likelihood is MEDIUM (broad export scope but no "
        "NSE evidence of anonymous access), or NetExec CONFIRMED root_escape=False on a "
        "host whose export scope is still CRITICAL/HIGH (effectively open to all clients "
        "or a wide CIDR). The second case matters on its own: knowing root is safe doesn't "
        "mean the export isn't broadly readable by every other account -- that's a "
        "data-exposure concern distinct from root-escape risk, not nothing."
    ),
    NFS_LOW: (
        "Everything that could be enumerated came back clean: either NetExec confirmed no "
        "root escape and the export scope is narrow, or no other elevated signal fired. "
        "Still worth a periodic recheck, but this is the baseline/expected state for a "
        "properly configured, narrowly-scoped NFS export."
    ),
}


def classify_finding(root_escape: str, root_escape_likelihood: str, scope_risk_val: str,
                      showmount_ok: bool, exports_present: bool) -> str:
    """
    Derives ONE of the 5 NFS_* categories for a single export/row (or a
    showmount-failed/no-exports placeholder row). Checked TOP TO BOTTOM --
    first match wins. Do not reorder: this priority order is a deliberate
    security judgment call, not an accident of implementation.

      1. CRITICAL -- root_escape == "TRUE" (nxc-confirmed). Wins regardless
         of every other signal, including an otherwise-failed enumeration --
         a confirmed escape always warrants a ticket.
      2. UNKNOWN -- enumeration didn't succeed (showmount failed, or
         succeeded but produced no parseable exports) AND root_escape isn't
         a confirmed TRUE. Deliberately checked before the HIGH/MEDIUM/LOW
         likelihood checks below, since scope_risk/root_escape_likelihood
         are not meaningful without a successfully-enumerated export to
         compute them from.
      3. HIGH -- root_escape is UNKNOWN or a confirmed FALSE, but the
         INFERRED root_escape_likelihood is VERY_HIGH or HIGH.
      4. MEDIUM -- INFERRED likelihood is MEDIUM, OR root_escape is a
         confirmed FALSE but the export's scope_risk is still CRITICAL/HIGH
         (root is safe, but the export is still broadly reachable -- a
         distinct, non-zero, data-exposure concern).
      5. LOW -- fallback: everything else that was successfully enumerated.

    One genuinely ambiguous case, and how it was resolved: root_escape=="FALSE"
    (NetExec actively confirmed no root escape) on a host where showmount ALSO
    failed. That can only happen because nxc and showmount are independent
    tools probing independently -- nxc doesn't require showmount to succeed.
    Despite having an explicit CONFIRMED-safe root_escape verdict in hand,
    this still lands in UNKNOWN rather than LOW, because the UNKNOWN bucket
    is about "export scope could not be assessed at all" (scope_risk is UNK
    in that situation) -- a confirmed-safe root does not tell you anything
    about whether the export is broadly readable by non-root accounts, so
    downgrading to LOW would overstate how much was actually verified here.
    This follows the spec's literal priority order (check 2 before check 3)
    rather than special-casing a "mixed" bucket.
    """
    if root_escape == "TRUE":
        return NFS_CRITICAL
    if (not showmount_ok) or (not exports_present):
        return NFS_UNKNOWN
    if root_escape in ("UNKNOWN", "FALSE") and root_escape_likelihood in ("VERY_HIGH", "HIGH"):
        return NFS_HIGH
    if root_escape_likelihood == "MEDIUM" or (root_escape == "FALSE" and scope_risk_val in ("CRITICAL", "HIGH")):
        return NFS_MEDIUM
    return NFS_LOW


def worst_category(categories) -> str:
    """Pick the most severe category present, using NFS_ORDER's display
    ordering (CRITICAL worst ... LOW, with UNKNOWN only chosen if nothing
    else is present -- it is not a severity level)."""
    present = set(categories)
    for cat in NFS_ORDER:
        if cat in present:
            return cat
    return NFS_UNKNOWN


def category_for_row(row: dict) -> str:
    """Re-derive a detail row's classify_finding() category from the row
    dict alone (its 'note' field unambiguously encodes showmount_ok /
    exports_present by construction -- see build_rows_for_host()). Used
    everywhere a row has already been serialized to/from a dict (CSV
    reload, xlsx building, Phase 2 progress stats) so there is exactly one
    place this re-derivation logic lives."""
    note = str(row.get("note", ""))
    showmount_ok = not note.startswith("showmount_failed")
    exports_present = showmount_ok and note != "no_exports_parsed"
    return classify_finding(row.get("root_escape", "UNKNOWN"), row.get("root_escape_likelihood", "UNKNOWN"),
                             row.get("scope_risk", "UNK"), showmount_ok, exports_present)


# =============================================================================
# TEXT SANITIZATION (ported verbatim from telnet_spray.py)
# =============================================================================
# Export paths and allowed-client strings come straight off the wire from
# showmount/NSE output on the scanned server; hostnames come from reverse
# DNS; nxc's evidence line reflects server-controlled content too. All of it
# is attacker-influenceable by design (it's literally what this tool
# audits), same category of risk as every sibling script's free-text fields.

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_text(value: str, max_len: int = 2000) -> str:
    if not value:
        return ""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _CONTROL_CHAR_RE.sub("", value)
    value = value.strip()
    if len(value) > max_len:
        value = value[:max_len] + " ...(truncated)"
    return value


# CSV/Excel formula injection (CWE-1236): prefixing a leading quote onto any
# value starting with a formula-trigger character forces plain-text
# interpretation, matching the fix already applied in telnet_spray.py /
# sslspray.py.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_formula(value):
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_CHARS):
        return "'" + value
    return value


# Free-text fields that are attacker-influenceable and must be sanitized at
# capture time + neutralized at CSV/xlsx write time.
_SANITIZE_FIELDS = ("hostname", "export_path", "allowed_clients", "risk_reason",
                     "why_flagged", "root_escape_evidence", "nfs_versions")


# =============================================================================
# LOGGING / PROGRESS DISPLAY (ported near-verbatim from the sibling scripts)
# =============================================================================

_progress_lock = threading.Lock()
_last_progress_len = 0


class ProgressAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        global _last_progress_len
        with _progress_lock:
            if _last_progress_len:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
            super().emit(record)
            _last_progress_len = 0


def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("nfs_no_root_squash")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def draw_progress_line(line: str) -> None:
    global _last_progress_len
    with _progress_lock:
        pad = max(0, _last_progress_len - len(line))
        sys.stdout.write("\r" + line + (" " * pad))
        sys.stdout.flush()
        _last_progress_len = len(line)


def finish_progress_line() -> None:
    global _last_progress_len
    with _progress_lock:
        if _last_progress_len:
            sys.stdout.write("\n")
            sys.stdout.flush()
        _last_progress_len = 0


def fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def render_bar(pct: Optional[float], width: int = 30) -> str:
    if pct is None:
        return "[" + "-" * width + "]  n/a"
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100.0)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {pct:5.1f}%"


# =============================================================================
# DEPENDENCY / VALIDATION HELPERS (mirrors the sibling scripts)
# =============================================================================

def check_external_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def validate_subnets(raw_subnets: List[str], logger: logging.Logger) -> List[ipaddress.IPv4Network]:
    networks = []
    for entry in raw_subnets:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error(f"Skipping invalid CIDR '{entry}': {exc}")
    return networks


def subnet_for_ip(ip: str, networks: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    for net in networks:
        if addr in net:
            return str(net)
    return "UNKNOWN"


def run_cmd(cmd: List[str], timeout: int = 0) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout if timeout and timeout > 0 else None
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, "[timeout]"
    except Exception as e:  # noqa: BLE001 - one bad subprocess must not kill the scan
        return 1, f"[error] {e}"


def _is_retryable(rc: int, out: str) -> bool:
    """Only a transient, timeout/connection-style failure is retried -- a
    clean rc!=0 with real stdout (e.g. showmount's own 'clnt_create: RPC:
    Program not registered' rejection) is a deterministic property of the
    host, not a transient miss, same 'only retry a transient failure' rule
    the sibling scripts use for their own retry loops. rc==124 is our
    run_cmd()'s own timeout marker; a rc!=0 result whose output starts with
    '[error]' means run_cmd() caught an exception while launching/talking to
    the subprocess (e.g. a connection-style OSError), which is the other
    transient case worth retrying."""
    return rc == 124 or (isinstance(out, str) and out.startswith("[error]"))


def _run_cmd_with_retry(cmd: List[str], timeout: int, retries: int,
                         logger: logging.Logger, label: str, ip: str) -> Tuple[int, str]:
    rc, out = run_cmd(cmd, timeout=timeout)
    attempt = 0
    while _is_retryable(rc, out) and attempt < max(0, retries):
        attempt += 1
        logger.debug(f"{label} for {ip} hit a transient failure (attempt {attempt}); retrying...")
        rc, out = run_cmd(cmd, timeout=timeout)
    return rc, out


# =============================================================================
# Hostname resolution (primary + fallback chain, preserved from the
# original script -- richer than the sibling scripts' single
# socket.gethostbyaddr() call, kept because it measurably improves hit rate
# in this environment's corporate DNS layout)
# =============================================================================

def resolve_ptr_socket(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return (name or "").strip().rstrip(".")
    except Exception:
        return ""


def resolve_fqdn_socket(ip: str) -> str:
    try:
        fqdn = socket.getfqdn(ip)
        fqdn = (fqdn or "").strip().rstrip(".")
        if fqdn == ip:
            return ""
        return fqdn
    except Exception:
        return ""


def resolve_ptr_dig(ip: str, dig_path: Optional[str], timeout: float) -> str:
    if not dig_path:
        return ""
    rc, out = run_cmd([dig_path, "+short", "-x", ip], timeout=timeout)
    if rc != 0 or not out.strip():
        return ""
    for line in out.splitlines():
        line = line.strip().rstrip(".")
        if line:
            return line
    return ""


def resolve_ptr_host(ip: str, host_path: Optional[str], timeout: float) -> str:
    if not host_path:
        return ""
    rc, out = run_cmd([host_path, ip], timeout=timeout)
    if rc != 0 or not out.strip():
        return ""
    for line in out.splitlines():
        line = line.strip()
        if "domain name pointer" in line:
            parts = line.split()
            if parts:
                return parts[-1].rstrip(".")
    return ""


def _call_with_hard_timeout(func, timeout: float):
    """Runs func() with an ACTUAL enforced wall-clock timeout.
    socket.setdefaulttimeout() does NOT bound socket.gethostbyaddr() (or
    getfqdn()) -- confirmed by direct testing against an unresolvable
    address: it kept blocking for several seconds regardless of the
    requested timeout value. Those calls hit the OS's own blocking resolver
    directly and never consult Python's socket-level timeout at all - a
    well-known CPython gotcha, not a typo. A throwaway single-worker
    executor gives up and returns None if func() hasn't completed in time;
    shutdown(wait=False) means the orphaned thread is left to finish
    resolving (or for the OS resolver to time out on its own) in the
    background rather than blocking this call."""
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func)
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        return None
    finally:
        executor.shutdown(wait=False)


def resolve_hostname(ip: str, dig_path: Optional[str], host_path: Optional[str],
                      timeout: float) -> Dict[str, str]:
    # See _call_with_hard_timeout()'s docstring for why this can't just be
    # a socket.setdefaulttimeout() wrapper (it does not bound these two
    # specific calls); the dig/host fallbacks below already have a real,
    # enforced subprocess timeout and don't need this wrapper.
    ptr = _call_with_hard_timeout(lambda: resolve_ptr_socket(ip), timeout)
    if ptr:
        return {"hostname": _sanitize_text(ptr), "dns_note": "ptr(socket)"}
    fqdn = _call_with_hard_timeout(lambda: resolve_fqdn_socket(ip), timeout)
    if fqdn:
        return {"hostname": _sanitize_text(fqdn), "dns_note": "fqdn(socket)"}
    ptr = resolve_ptr_dig(ip, dig_path, timeout)
    if ptr:
        return {"hostname": _sanitize_text(ptr), "dns_note": "ptr(dig)"}
    ptr = resolve_ptr_host(ip, host_path, timeout)
    if ptr:
        return {"hostname": _sanitize_text(ptr), "dns_note": "ptr(host)"}
    return {"hostname": "", "dns_note": ""}


# =============================================================================
# PHASE 1a: MASSCAN DISCOVERY (ported near-verbatim from the sibling scripts)
# =============================================================================

class MasscanStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s+done", line)
        eta_m = re.search(r"done,\s*([\d:]+)\s*remaining", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _masscan_stderr_reader(proc: subprocess.Popen, status: MasscanStatus) -> None:
    buf = b""
    stream = proc.stderr
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def build_masscan_command(masscan_path: str, subnets: List[str], rate: int, retries: int,
                           output_file: str, interface: Optional[str]) -> List[str]:
    cmd = [masscan_path, "-p", str(NFS_PORT), "--rate", str(rate),
           "--retries", str(retries), "-oL", output_file]
    if interface:
        cmd += ["-e", interface]
    cmd += subnets
    return cmd


def parse_masscan_list_output(path: str, start_offset: int = 0) -> Tuple[List[Tuple[str, int, str]], int]:
    records: List[Tuple[str, int, str]] = []
    if not os.path.exists(path):
        return records, start_offset
    with open(path, "rb") as f:
        f.seek(start_offset)
        chunk = f.read()
    if not chunk:
        return records, start_offset
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return records, start_offset
    usable, new_offset = chunk[:last_newline + 1], start_offset + last_newline + 1
    for raw_line in usable.split(b"\n"):
        line = raw_line.decode(errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        status, proto, port_s, ip, _ts = parts[:5]
        if status != "open":
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        records.append((ip, port, proto))
    return records, new_offset


def run_masscan_phase1(masscan_path: str, subnets: List[str], rate: int, retries: int,
                        output_file: str, interface: Optional[str],
                        logger: logging.Logger, stop_event: threading.Event
                        ) -> Tuple[List[Tuple[str, int, str]], bool]:
    """Returns (records, succeeded). succeeded=False signals the caller to
    fall back to nmap discovery."""
    cmd = build_masscan_command(masscan_path, subnets, rate, retries, output_file, interface)
    logger.info("Phase 1 - DISCOVERY starting (masscan)")
    logger.debug(f"Masscan command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"masscan executable not found at '{masscan_path}'.")
        return [], False
    except PermissionError as exc:
        logger.error(f"Permission error launching masscan: {exc}. "
                      f"Masscan typically requires root/administrator privileges.")
        return [], False
    except OSError as exc:
        logger.error(f"Failed to launch masscan: {exc}")
        return [], False

    status = MasscanStatus()
    reader_thread = threading.Thread(target=_masscan_stderr_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    start_time = time.time()
    nfs_count = 0
    offset = 0
    seen: set = set()

    def _drain_new_records() -> None:
        nonlocal offset, nfs_count
        new_records, offset = parse_masscan_list_output(output_file, offset)
        for ip, port, _proto in new_records:
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            if port == NFS_PORT:
                nfs_count += 1

    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating masscan...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            _drain_new_records()

            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta

            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY (masscan) {bar} | NFS hosts found: {nfs_count} | "
                     f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                time.sleep(0.3)
                _drain_new_records()
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    succeeded = proc.returncode in (0, None) or stop_event.is_set()
    if not succeeded:
        logger.warning(f"masscan exited with return code {proc.returncode}; "
                        f"falling back to nmap discovery...")

    final_records, _ = parse_masscan_list_output(output_file, 0)
    logger.info(f"Phase 1 - DISCOVERY (masscan) complete. NFS-port hits: {nfs_count}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return final_records, succeeded


# =============================================================================
# PHASE 1b: NMAP FALLBACK DISCOVERY (genuine feature kept from the original
# script -- see module docstring's DELIBERATE DEVIATION section -- now
# driven through the same draw_progress_line()/render_bar() primitives as
# masscan instead of its own bespoke progress bar)
# =============================================================================

class NmapDiscoveryStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"([\d.]+)\s*%\s*done", line)
        eta_m = re.search(r"\(([\d:]+)\s*remaining\)", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _nmap_stdout_reader(proc: subprocess.Popen, status: NmapDiscoveryStatus) -> None:
    """Read nmap's combined stdout/stderr unbuffered, splitting on both '\\n'
    and '\\r' -- nmap's --stats-every lines are newline-terminated, but we
    read in small chunks regardless to keep updates live."""
    buf = b""
    stream = proc.stdout
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def _parse_nmap_grep(path: str) -> set:
    """nmap -oG lines look like: 'Host: 10.0.0.5 () Ports: 2049/open/tcp//nfs///'."""
    hosts = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Host:") and "Ports:" in line and "/open/" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        try:
                            ipaddress.ip_address(ip)
                            hosts.add(ip)
                        except Exception:
                            continue
    except FileNotFoundError:
        pass
    return hosts


def run_nmap_discovery_phase1(nmap_path: str, subnets: List[str], timing: str, min_rate: int,
                               stats_every: str, output_file: str,
                               logger: logging.Logger, stop_event: threading.Event) -> List[str]:
    base = [nmap_path, "-n", "-p", str(NFS_PORT), "--open", f"-{timing}",
            "--stats-every", stats_every, "-oG", output_file]
    if min_rate:
        base = [nmap_path, "-n", "--min-rate", str(min_rate), "-p", str(NFS_PORT), "--open",
                f"-{timing}", "--stats-every", stats_every, "-oG", output_file]
    cmd = base + subnets
    logger.info(f"Phase 1 - DISCOVERY starting (nmap fallback, {timing}, min-rate={min_rate})")
    logger.debug(f"Nmap discovery command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    except FileNotFoundError:
        logger.error(f"nmap executable not found at '{nmap_path}'.")
        return []
    except PermissionError as exc:
        logger.error(f"Permission error launching nmap: {exc}. "
                      f"SYN scanning typically requires root/administrator privileges.")
        return []
    except OSError as exc:
        logger.error(f"Failed to launch nmap: {exc}")
        return []

    status = NmapDiscoveryStatus()
    reader_thread = threading.Thread(target=_nmap_stdout_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    start_time = time.time()
    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating nmap discovery...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta
            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY (nmap fallback) {bar} | "
                     f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    if proc.returncode not in (0, None) and not stop_event.is_set():
        logger.warning(f"nmap discovery exited with return code {proc.returncode}; "
                        f"results collected so far will still be used.")

    hosts = sorted(_parse_nmap_grep(output_file))
    logger.info(f"Phase 1 - DISCOVERY (nmap fallback) complete. NFS-port hits: {len(hosts)}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return hosts


def discover_nfs_hosts(masscan_path: Optional[str], nmap_path: str, args: argparse.Namespace,
                        output_dir: str, date_suffix: str,
                        logger: logging.Logger, stop_event: threading.Event) -> List[str]:
    """Masscan-preferred, nmap-fallback -- see module docstring's DELIBERATE
    DEVIATION section for why the fallback is kept at all."""
    if masscan_path:
        masscan_out = args.masscan_output_file or os.path.join(
            output_dir, f".masscan_output_{date_suffix}.txt")
        records, ok = run_masscan_phase1(masscan_path, SUBNETS, args.masscan_rate,
                                          args.masscan_retries, masscan_out, args.interface,
                                          logger, stop_event)
        if ok:
            return sorted({ip for ip, port, _ in records if port == NFS_PORT})
        if stop_event.is_set():
            return sorted({ip for ip, port, _ in records if port == NFS_PORT})
        # fall through to nmap fallback
    else:
        logger.info("masscan not found on PATH; using nmap for discovery "
                     "(install masscan for much faster large-range scans).")

    nmap_out = os.path.join(output_dir, f".nmap_discovery_{date_suffix}.gnmap")
    hosts = run_nmap_discovery_phase1(nmap_path, SUBNETS, args.nmap_timing, args.nmap_min_rate,
                                       DEFAULT_NMAP_STATS_EVERY, nmap_out, logger, stop_event)
    try:
        os.unlink(nmap_out)
    except OSError:
        pass
    return hosts


# =============================================================================
# showmount parsing
# =============================================================================

def parse_showmount_exports(output: str) -> List[Tuple[str, str]]:
    exports = []
    lines = [l.rstrip() for l in output.splitlines() if l.strip()]
    for l in lines:
        if l.lower().startswith("export list for"):
            continue
        parts = l.split()
        if not parts:
            continue
        export_path = parts[0]
        allowed = " ".join(parts[1:]) if len(parts) > 1 else ""
        exports.append((export_path, allowed))
    return exports


# =============================================================================
# Nmap NSE enrichment (read-only)
# =============================================================================

def nmap_nse_for_host(nmap_path: str, ip: str, timing: str, timeout: int) -> Tuple[int, str]:
    cmd = [nmap_path, "-n", "-p", "111,2049", f"-{timing}", "--script", NSE_SCRIPTS, ip]
    return run_cmd(cmd, timeout=timeout)


def infer_access_from_nse(out: str) -> Dict[str, str]:
    """
    Lightweight inference:
      - listing_access: YES if output appears to show directory listing content
      - statfs_access : YES if output appears to show filesystem stats content
    """
    u = (out or "").upper()

    listing_access = "NO"
    statfs_access = "NO"

    if any(k in u for k in ["ACCESS DENIED", "PERMISSION DENIED"]):
        return {"listing_access": "NO", "statfs_access": "NO"}

    if "NFS-LS" in u and ("DIRECTORY" in u or "FILES:" in u):
        listing_access = "YES"

    if "NFS-STATFS" in u and any(k in u for k in ["FILESYSTEM", "BLOCKS", "TOTAL", "FREE", "BYTES"]):
        statfs_access = "YES"

    return {"listing_access": listing_access, "statfs_access": statfs_access}


# =============================================================================
# NetExec (nxc) NFS enrichment -> CONFIRMED root escape verdict
# =============================================================================

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_NXC_ESCAPE_RE = re.compile(r"root\s*escape\s*:\s*(true|false)", re.IGNORECASE)
_NXC_VERS_RE = re.compile(r"Supported NFS versions\s*:\s*\(([^)]*)\)", re.IGNORECASE)


def nxc_nfs_for_host(nxc_path: Optional[str], ip: str, timeout: int) -> Tuple[int, str]:
    """Run `nxc nfs <ip>` (NetExec). Returns (rc, output). No-op if nxc absent."""
    if not nxc_path:
        return 0, ""
    return run_cmd([nxc_path, "nfs", ip], timeout=timeout)


def parse_nxc_nfs(out: str) -> Dict[str, str]:
    """
    Parse NetExec NFS output, e.g.:
      'NFS  10.17.67.150  20048  ...  [*] Supported NFS versions: (3, 4) (root escape:False)'
    Returns root_escape (TRUE/FALSE/UNKNOWN), nfs_versions, and the evidence line.
    """
    text = _ANSI_RE.sub("", out or "")
    root_escape = "UNKNOWN"
    versions = ""
    evidence = ""

    m = _NXC_ESCAPE_RE.search(text)
    if m:
        root_escape = "TRUE" if m.group(1).lower() == "true" else "FALSE"

    v = _NXC_VERS_RE.search(text)
    if v:
        versions = v.group(1).strip()

    for l in text.splitlines():
        low = l.lower()
        if "root escape" in low or "supported nfs versions" in low:
            evidence = l.strip()
            break

    return {"root_escape": root_escape, "nfs_versions": versions, "evidence": evidence}


# =============================================================================
# Risk scoring + ticket text (ported verbatim -- detection logic unchanged)
# =============================================================================

WILDCARD_ALL = {"*", "(everyone)", "everyone", "(all)", "(all_hosts)", "0.0.0.0/0", "::/0"}


def _tokens(allowed: str) -> List[str]:
    return [t.strip(",") for t in allowed.split() if t.strip()]


def exported_to_all(allowed: str) -> bool:
    return any(t.lower() in WILDCARD_ALL for t in _tokens(allowed))


def all_client_token(allowed: str) -> str:
    for t in _tokens(allowed):
        if t.lower() in WILDCARD_ALL:
            return t
    return "*"


def everyone_note(token: str) -> str:
    if token.lower() in ("(everyone)", "everyone"):
        return " (NetApp '(everyone)' = the export is open to ALL NFS clients, equivalent to '*')"
    if token.lower() in ("(all)", "(all_hosts)"):
        return " ('(all)' = the export is open to ALL NFS clients, equivalent to '*')"
    return ""


def is_broad_scope(allowed: str) -> bool:
    if not allowed:
        return False
    for t in _tokens(allowed):
        if t.lower() in WILDCARD_ALL:
            return True
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                # IPv4 /16-or-wider and IPv6 /32-or-wider are both "broad" in
                # practical address-space terms (/32 alone covers 2^96
                # addresses) -- the original IPv4Network-only check let an
                # equivalently wide-open IPv6 export (e.g. "2001:db8::/32")
                # fall through unclassified unless it used the literal
                # "::/0" wildcard already caught above.
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 16:
                    return True
                if isinstance(net, ipaddress.IPv6Network) and net.prefixlen <= 32:
                    return True
            except Exception:
                pass
    return False


def scope_risk(allowed: str) -> str:
    if not allowed:
        return "UNK"
    if exported_to_all(allowed):
        return "CRITICAL"
    if is_broad_scope(allowed):
        return "HIGH"
    if len(_tokens(allowed)) >= 5:
        return "MED"
    return "LOW"


def root_escape_likelihood_for_export(allowed: str, listing_access: str, statfs_access: str) -> Tuple[str, str]:
    if not allowed:
        return ("UNKNOWN", "No allowed_clients data from showmount")

    all_clients = exported_to_all(allowed)
    broad = is_broad_scope(allowed)
    has_access_evidence = (listing_access == "YES" or statfs_access == "YES")

    if all_clients and has_access_evidence:
        return ("VERY_HIGH", "Exported to all clients and NSE indicates anonymous listing/statfs access")
    if broad and has_access_evidence:
        return ("HIGH", "Broad export scope (>=/16 or all-clients) and NSE indicates listing/statfs access")
    if (all_clients or broad) and not has_access_evidence:
        return ("MEDIUM", "Broad export scope, but NSE did not confirm listing/statfs access")
    if has_access_evidence:
        # Scope looks narrow by allowed_clients, but NSE still got real
        # anonymous listing/statfs content back -- either the scanning host
        # happens to be in the allowed range, or the server isn't actually
        # enforcing the export restriction it advertises. Either way this is
        # real, observed anonymous access, not nothing: MEDIUM, not LOW.
        return ("MEDIUM", "Narrower export scope, but NSE still confirmed anonymous listing/statfs "
                           "access -- the advertised client restriction may not be effectively enforced")
    return ("LOW", "Narrower export scope and no NSE evidence of anonymous access")


def risk_reason_and_why(export_path: str, allowed: str, scope: str, listing_access: str, statfs_access: str,
                        likelihood: str, showmount_ok: bool) -> Tuple[str, str]:
    if not showmount_ok:
        rr = "NFS detected but exports not enumerable (showmount failed)"
        wf = ("NFS is reachable on this host, but exports could not be enumerated via showmount; "
              "confirm export configuration and ensure client scoping/root squashing are enforced.")
        return rr, wf

    if not allowed:
        rr = "Exports enumerated but allowed_clients missing/unknown"
        wf = (f"NFS export '{export_path}' was enumerated, but allowed client scope could not be determined remotely; "
              f"verify export restrictions and root squashing on the server.")
        return rr, wf

    to_all = exported_to_all(allowed)
    broad = is_broad_scope(allowed)
    access_bits = []
    if listing_access == "YES":
        access_bits.append("directory listing")
    if statfs_access == "YES":
        access_bits.append("statfs")
    access_txt = " and ".join(access_bits) if access_bits else "no anonymous enumeration evidence"

    if to_all:
        tok = all_client_token(allowed)
        note = everyone_note(tok)
        rr = f"Export open to ALL clients ({tok}); NSE {access_txt}"
        wf = (f"NFS export '{export_path}' is accessible to all clients ({tok}){note} and remote enumeration indicates {access_txt}; "
              f"restrict allowed clients and verify export options (root_squash/no_root_squash) on the server.")
        return rr, wf

    if broad:
        rr = f"Broad client scope (>=/16); NSE {access_txt}"
        wf = (f"NFS export '{export_path}' is available to a broad network range ({allowed}) and remote enumeration indicates {access_txt}; "
              f"restrict allowed clients and verify root squashing is enabled.")
        return rr, wf

    rr = f"NFS export scoped to specific clients; NSE {access_txt}"
    wf = (f"NFS export '{export_path}' appears limited to specific client(s) ({allowed}); remote enumeration indicates {access_txt}. "
          f"Maintain least-privilege client scoping and validate export options as needed.")
    return rr, wf


def max_severity(a: str, b: str) -> str:
    order = ["UNK", "LOW", "MED", "HIGH", "CRITICAL"]
    try:
        return a if order.index(a) >= order.index(b) else b
    except Exception:
        return a or b


def max_likelihood(a: str, b: str) -> str:
    order = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
    try:
        return a if order.index(a) >= order.index(b) else b
    except Exception:
        return a or b


# =============================================================================
# PHASE 2: PER-HOST WORKER POOL
# =============================================================================

@dataclass
class DiscoveredHost:
    ip: str
    subnet: str = "UNKNOWN"


@dataclass
class HostPhase2Raw:
    ip: str
    hostname: str
    dns_note: str
    sm_rc: int
    sm_out: str
    nse_rc: int
    nse_out: str
    nxc_rc: int
    nxc_out: str


@dataclass
class Phase2Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    total: int = 0
    completed: int = 0
    active_workers: int = 0
    category_counts: Dict[str, int] = field(default_factory=lambda: {c: 0 for c in NFS_ORDER})
    confirmed_root_escape: int = 0


DETAIL_FIELDS = [
    "subnet", "server_ip", "hostname", "dns_note",
    "export_path", "allowed_clients",
    "scope_risk", "listing_access", "statfs_access",
    "root_escape", "nfs_versions", "root_escape_confidence", "root_escape_evidence",
    "root_escape_likelihood", "root_escape_basis",
    "verification_required",
    "risk_reason", "why_flagged",
    "note",
]

SUMMARY_FIELDS = [
    "subnet", "server_ip", "hostname", "dns_note",
    "exports_count", "exports_sample",
    "highest_scope_risk",
    "root_escape", "nfs_versions", "root_escape_confidence", "root_escape_evidence",
    "highest_root_escape_likelihood",
    "verification_required",
    "risk_reason", "why_flagged",
    "showmount_status", "nse_status", "nxc_status",
]

ROOTESCAPE_FIELDS = [
    "subnet", "server_ip", "hostname",
    "root_escape", "nfs_versions", "root_escape_confidence", "root_escape_evidence",
    "highest_scope_risk", "exports_count", "exports_sample",
    "why_flagged",
]


def _sanitize_row(row: dict) -> dict:
    for f_ in _SANITIZE_FIELDS:
        if f_ in row and row[f_]:
            row[f_] = _sanitize_text(row[f_])
    return row


def scan_one_host(host: DiscoveredHost, args: argparse.Namespace, logger: logging.Logger,
                   showmount_path: str, nmap_path: str, nxc_path: Optional[str],
                   dig_path: Optional[str], host_path: Optional[str]) -> Optional[HostPhase2Raw]:
    """Outermost guard, matching ssh_vuln_scan.py's scan_one_host()
    convention: nothing in Phase 2 -- including the retry loop itself --
    may be allowed to propagate out and take the rest of the batch down."""
    try:
        return _scan_one_host_inner(host, args, logger, showmount_path, nmap_path, nxc_path,
                                     dig_path, host_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"scan_one_host({host.ip}) failed unexpectedly: {exc}")
        return None


def _scan_one_host_inner(host: DiscoveredHost, args: argparse.Namespace, logger: logging.Logger,
                          showmount_path: str, nmap_path: str, nxc_path: Optional[str],
                          dig_path: Optional[str], host_path: Optional[str]) -> HostPhase2Raw:
    ip = host.ip
    hn = resolve_hostname(ip, dig_path, host_path, DEFAULT_DNS_TIMEOUT)
    sm_rc, sm_out = _run_cmd_with_retry(
        [showmount_path, "-e", ip], args.showmount_timeout, args.retries, logger, "showmount", ip)
    nse_rc, nse_out = _run_cmd_with_retry(
        [nmap_path, "-n", "-p", "111,2049", f"-{args.nmap_timing}", "--script", NSE_SCRIPTS, ip],
        args.nse_timeout, args.retries, logger, "nmap NSE", ip)
    if nxc_path:
        nxc_rc, nxc_out = _run_cmd_with_retry(
            [nxc_path, "nfs", ip], args.nxc_timeout, args.retries, logger, "nxc", ip)
    else:
        nxc_rc, nxc_out = 0, ""
    return HostPhase2Raw(
        ip=ip, hostname=hn.get("hostname", ""), dns_note=hn.get("dns_note", ""),
        sm_rc=sm_rc, sm_out=sm_out, nse_rc=nse_rc, nse_out=nse_out, nxc_rc=nxc_rc, nxc_out=nxc_out,
    )


def build_rows_for_host(raw: HostPhase2Raw, subnet: str, nxc_available: bool
                         ) -> Tuple[List[dict], dict]:
    """Builds this host's detail rows + summary row. Preserves the original
    script's row-building logic verbatim; the only additions are
    sanitization of free-text fields and a classify_finding() category on
    every detail row."""
    ip = raw.ip
    hostname = raw.hostname
    dns_note = raw.dns_note

    nse_access = infer_access_from_nse(raw.nse_out)
    listing_access = nse_access["listing_access"]
    statfs_access = nse_access["statfs_access"]

    nxc_info = parse_nxc_nfs(raw.nxc_out)
    root_escape = nxc_info["root_escape"]
    nfs_versions = nxc_info["nfs_versions"]
    nxc_evidence = nxc_info["evidence"]
    re_confidence = "CONFIRMED" if root_escape in ("TRUE", "FALSE") else "INFERRED"

    nxc_fields = {
        "root_escape": root_escape,
        "nfs_versions": nfs_versions,
        "root_escape_confidence": re_confidence,
        "root_escape_evidence": nxc_evidence,
    }

    summary = {
        "subnet": subnet,
        "server_ip": ip,
        "hostname": hostname,
        "dns_note": dns_note,
        "exports_count": "0",
        "exports_sample": "",
        "highest_scope_risk": "UNK",
        "root_escape": root_escape,
        "nfs_versions": nfs_versions,
        "root_escape_confidence": re_confidence,
        "root_escape_evidence": nxc_evidence,
        "highest_root_escape_likelihood": "UNKNOWN",
        "verification_required": "NO",
        "risk_reason": "",
        "why_flagged": "",
        "showmount_status": f"rc={raw.sm_rc}",
        "nse_status": f"rc={raw.nse_rc}",
        "nxc_status": f"rc={raw.nxc_rc}" + ("" if nxc_available else " (nxc not installed)"),
    }

    if root_escape == "TRUE":
        summary["verification_required"] = "YES"

    detail_rows: List[dict] = []
    row_categories: List[str] = []

    showmount_ok = (raw.sm_rc == 0 and raw.sm_out.strip() not in ("", "[timeout]"))

    if not showmount_ok:
        rr, wf = risk_reason_and_why("", "", "UNK", listing_access, statfs_access, "UNKNOWN", showmount_ok=False)
        if root_escape == "TRUE":
            rr = "CONFIRMED root escape (no_root_squash) via nxc; showmount not enumerable"
            wf = ("NetExec confirms root escape (no_root_squash=True) on this host; "
                  "exports could not be enumerated via showmount but root squashing is NOT enforced. "
                  "Remediate immediately (enable root_squash) and restrict client scope.")
        row = {
            "subnet": subnet, "server_ip": ip, "hostname": hostname, "dns_note": dns_note,
            "export_path": "", "allowed_clients": "",
            "scope_risk": "UNK", "listing_access": listing_access, "statfs_access": statfs_access,
            "root_escape_likelihood": "UNKNOWN",
            "root_escape_basis": "showmount failed; cannot enumerate exports",
            "verification_required": "YES",
            "risk_reason": rr, "why_flagged": wf,
            "note": f"showmount_failed rc={raw.sm_rc}",
        }
        row.update(nxc_fields)
        row = _sanitize_row(row)
        detail_rows.append(row)
        summary["verification_required"] = "YES"
        summary["risk_reason"] = rr
        summary["why_flagged"] = wf
        category = classify_finding(root_escape, "UNKNOWN", "UNK", showmount_ok=False, exports_present=False)
        row_categories.append(category)
        summary["highest_category"] = worst_category(row_categories)
        return detail_rows, _sanitize_row(summary)

    exports = parse_showmount_exports(raw.sm_out)
    if not exports:
        rr, wf = risk_reason_and_why("", "", "UNK", listing_access, statfs_access, "UNKNOWN", showmount_ok=True)
        if root_escape == "TRUE":
            rr = "CONFIRMED root escape (no_root_squash) via nxc; no exports parsed"
            wf = ("NetExec confirms root escape (no_root_squash=True) on this host; "
                  "enable root_squash and restrict client scope.")
        row = {
            "subnet": subnet, "server_ip": ip, "hostname": hostname, "dns_note": dns_note,
            "export_path": "", "allowed_clients": "",
            "scope_risk": "UNK", "listing_access": listing_access, "statfs_access": statfs_access,
            "root_escape_likelihood": "UNKNOWN",
            "root_escape_basis": "No exports parsed from showmount output",
            "verification_required": "YES",
            "risk_reason": rr, "why_flagged": wf,
            "note": "no_exports_parsed",
        }
        row.update(nxc_fields)
        row = _sanitize_row(row)
        detail_rows.append(row)
        summary["verification_required"] = "YES"
        summary["risk_reason"] = rr
        summary["why_flagged"] = wf
        category = classify_finding(root_escape, "UNKNOWN", "UNK", showmount_ok=True, exports_present=False)
        row_categories.append(category)
        summary["highest_category"] = worst_category(row_categories)
        return detail_rows, _sanitize_row(summary)

    summary["exports_count"] = str(len(exports))
    summary["exports_sample"] = ";".join([e[0] for e in exports[:5]])

    for export_path, allowed in exports:
        s_risk = scope_risk(allowed)
        likelihood, basis = root_escape_likelihood_for_export(allowed, listing_access, statfs_access)
        rr, wf = risk_reason_and_why(export_path, allowed, s_risk, listing_access, statfs_access, likelihood, showmount_ok=True)

        if root_escape == "TRUE":
            verify = "YES"
        elif root_escape == "FALSE":
            verify = "YES" if likelihood in ("VERY_HIGH", "HIGH") else "NO"
        else:
            verify = "YES" if likelihood in ("VERY_HIGH", "HIGH", "MEDIUM") else "NO"

        if root_escape == "TRUE":
            rr = f"CONFIRMED root escape (no_root_squash) via nxc; {rr}"
            wf = (f"NetExec confirms root escape (no_root_squash=True) on this host. {wf} "
                  f"This is exploitable for privilege escalation — enable root_squash and restrict client scope.")

        row = {
            "subnet": subnet, "server_ip": ip, "hostname": hostname, "dns_note": dns_note,
            "export_path": export_path, "allowed_clients": allowed,
            "scope_risk": s_risk, "listing_access": listing_access, "statfs_access": statfs_access,
            "root_escape_likelihood": likelihood,
            "root_escape_basis": basis,
            "verification_required": verify,
            "risk_reason": rr, "why_flagged": wf,
            "note": "root_escape via nxc (CONFIRMED); scope/NSE are supporting signals"
                    if root_escape in ("TRUE", "FALSE")
                    else "REMOTE_ENUMERATION_ONLY (nxc unavailable; root_escape not confirmed)",
        }
        row.update(nxc_fields)
        row = _sanitize_row(row)
        detail_rows.append(row)

        category = classify_finding(root_escape, likelihood, s_risk, showmount_ok=True, exports_present=True)
        row_categories.append(category)

        summary["highest_scope_risk"] = max_severity(summary["highest_scope_risk"], s_risk)
        summary["highest_root_escape_likelihood"] = max_likelihood(
            summary["highest_root_escape_likelihood"], likelihood)
        if verify == "YES":
            summary["verification_required"] = "YES"
            if not summary["risk_reason"] or root_escape == "TRUE" or likelihood in ("VERY_HIGH", "HIGH"):
                summary["risk_reason"] = rr
                summary["why_flagged"] = (
                    f"One or more NFS exports on this host are broadly accessible and/or allow anonymous enumeration; "
                    f"restrict allowed clients and verify export options (root_squash/no_root_squash). "
                    f"Evidence example: {wf}"
                )

    summary["highest_category"] = worst_category(row_categories)
    return detail_rows, _sanitize_row(summary)


def build_error_placeholder_row(ip: str, subnet: str) -> Tuple[List[dict], dict]:
    """Builds a placeholder detail row + summary row for a host that Phase 1
    confirmed has TCP/2049 open, but whose Phase 2 worker (scan_one_host)
    raised an unexpected exception. Without this, such a host would simply
    vanish from every report (detail/summary/root-escape CSVs, xlsx, and the
    'Total hosts with TCP/2049 open' count) with no trace besides a logged
    warning -- for a tool whose entire point is not to silently miss a
    potential no_root_squash host, that's the one outcome worth avoiding
    even when the probe itself failed. note is deliberately prefixed
    'showmount_failed' so category_for_row() derives showmount_ok=False
    from it the same way a real showmount failure would, landing this row
    in NFS_UNKNOWN rather than any severity bucket we can't actually back up."""
    rr = "Phase 2 probe failed unexpectedly (see log for the exception) - host not enumerated"
    wf = (f"NFS was confirmed open on {ip} in Phase 1, but the Phase 2 enumeration worker "
          f"raised an unexpected error before showmount/NSE/nxc could run; re-scan this host "
          f"manually to get a real verdict.")
    row = {
        "subnet": subnet, "server_ip": ip, "hostname": "", "dns_note": "",
        "export_path": "", "allowed_clients": "",
        "scope_risk": "UNK", "listing_access": "NO", "statfs_access": "NO",
        "root_escape": "UNKNOWN", "nfs_versions": "", "root_escape_confidence": "INFERRED",
        "root_escape_evidence": "", "root_escape_likelihood": "UNKNOWN",
        "root_escape_basis": "Phase 2 worker raised an unexpected exception; see log",
        "verification_required": "YES",
        "risk_reason": rr, "why_flagged": wf,
        "note": "showmount_failed rc=-1 (scan_error - see log)",
    }
    row = _sanitize_row(row)
    summary = {
        "subnet": subnet, "server_ip": ip, "hostname": "", "dns_note": "",
        "exports_count": "0", "exports_sample": "",
        "highest_scope_risk": "UNK",
        "root_escape": "UNKNOWN", "nfs_versions": "", "root_escape_confidence": "INFERRED",
        "root_escape_evidence": "",
        "highest_root_escape_likelihood": "UNKNOWN",
        "verification_required": "YES",
        "risk_reason": rr, "why_flagged": wf,
        "showmount_status": "not run (scan error)", "nse_status": "not run (scan error)",
        "nxc_status": "not run (scan error)",
        "highest_category": NFS_UNKNOWN,
    }
    return [row], _sanitize_row(summary)


def render_phase2_line(stats: Phase2Stats, start_time: float) -> str:
    with stats.lock:
        completed = stats.completed
        total = stats.total
        active = stats.active_workers
        rc = dict(stats.category_counts)
        confirmed = stats.confirmed_root_escape
    pct = (completed / total * 100.0) if total else 0.0
    elapsed = time.time() - start_time
    if 0 < completed < total:
        eta = fmt_elapsed((elapsed / completed) * (total - completed))
    elif completed >= total and total > 0:
        eta = "00:00:00"
    else:
        eta = "n/a"
    bar = render_bar(pct)
    return (f"Phase 2 - NFS AUDIT {bar} | Completed: {completed}/{total} | "
            f"Workers: {active} | Confirmed root-escape: {confirmed} | "
            f"Crit:{rc[NFS_CRITICAL]} High:{rc[NFS_HIGH]} Med:{rc[NFS_MEDIUM]} "
            f"Low:{rc[NFS_LOW]} Unknown:{rc[NFS_UNKNOWN]} | "
            f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta}")


def run_phase2(hosts: List[DiscoveredHost], args: argparse.Namespace, logger: logging.Logger,
               stop_event: threading.Event, showmount_path: str, nmap_path: str,
               nxc_path: Optional[str], dig_path: Optional[str], host_path: Optional[str]
               ) -> Tuple[List[dict], Dict[str, dict]]:
    stats = Phase2Stats()
    stats.total = len(hosts)
    detail_rows: List[dict] = []
    host_summary: Dict[str, dict] = {}
    start_time = time.time()
    nxc_available = nxc_path is not None
    logger.info(f"Phase 2 - NFS AUDIT starting ({stats.total} hosts, {args.workers} workers)")

    def wrapped(host: DiscoveredHost) -> Optional[HostPhase2Raw]:
        with stats.lock:
            stats.active_workers += 1
        try:
            return scan_one_host(host, args, logger, showmount_path, nmap_path, nxc_path,
                                  dig_path, host_path)
        finally:
            with stats.lock:
                stats.active_workers -= 1

    host_by_ip = {h.ip: h for h in hosts}

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(wrapped, host): host for host in hosts}
        try:
            for future in as_completed(futures):
                host = futures[future]
                raw = future.result()
                with stats.lock:
                    stats.completed += 1
                if raw is not None:
                    rows, summary_row = build_rows_for_host(raw, host_by_ip[host.ip].subnet, nxc_available)
                else:
                    # scan_one_host() hit an unexpected exception (already
                    # logged there) -- this host was confirmed open in
                    # Phase 1 and must not simply vanish from every report;
                    # see build_error_placeholder_row()'s own docstring.
                    rows, summary_row = build_error_placeholder_row(host.ip, host_by_ip[host.ip].subnet)
                detail_rows.extend(rows)
                host_summary[host.ip] = summary_row
                with stats.lock:
                    for row in rows:
                        stats.category_counts[category_for_row(row)] += 1
                    if summary_row.get("root_escape") == "TRUE":
                        stats.confirmed_root_escape += 1
                draw_progress_line(render_phase2_line(stats, start_time))
                if stop_event.is_set():
                    logger.warning("Interrupt received, cancelling remaining audits...")
                    for f in futures:
                        f.cancel()
                    break
        finally:
            finish_progress_line()

    logger.info(f"Phase 2 - NFS AUDIT complete. {stats.completed}/{stats.total} hosts "
                f"probed, finished in {fmt_elapsed(time.time() - start_time)}.")
    return detail_rows, host_summary


# =============================================================================
# CSV
# =============================================================================

def _write_csv(path: str, fieldnames: List[str], rows: List[dict], logger: logging.Logger,
                label: str) -> bool:
    """Shared open/DictWriter/sanitize/writerow/log mechanics for all three
    CSV outputs below -- previously copy-pasted three times with slowly
    drifting wording; a future fix to the shared mechanics (a new sanitized
    field, broader exception handling) now only needs to happen once.
    Returns True on success, False on a caught write failure."""
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                out_row = {k: r.get(k, "") for k in fieldnames}
                for f_ in _SANITIZE_FIELDS:
                    if f_ in out_row:
                        out_row[f_] = _neutralize_formula(out_row[f_])
                w.writerow(out_row)
        logger.info(f"{label} written to {path} ({len(rows)} row(s))")
        return True
    except OSError as exc:
        logger.error(f"Failed to write {label.lower()} to {path}: {exc}")
        return False


def write_detail_csv(rows: List[dict], path: str, logger: logging.Logger) -> None:
    _write_csv(path, DETAIL_FIELDS, rows, logger, "Detail CSV")


def write_summary_csv(host_summary: Dict[str, dict], path: str, logger: logging.Logger) -> None:
    rows = [host_summary[ip] for ip in sorted(host_summary.keys())]
    _write_csv(path, SUMMARY_FIELDS, rows, logger, "Summary CSV")


def write_rootescape_csv(host_summary: Dict[str, dict], path: str, logger: logging.Logger) -> int:
    confirmed_true = sorted(ip for ip, r in host_summary.items() if r.get("root_escape") == "TRUE")
    rows = [host_summary[ip] for ip in confirmed_true]
    _write_csv(path, ROOTESCAPE_FIELDS, rows, logger, "Root-escape CSV")
    return len(confirmed_true)


def _csv_field(r: dict, key: str, default: str = "") -> str:
    return r.get(key) or default


def read_rows_from_csv(csv_path: str, logger: logging.Logger) -> List[dict]:
    """Rebuild detail rows from a previously-written detail CSV (--from-csv).
    Every free-text field is re-sanitized here too, so a hand-edited or
    stale CSV can't reach openpyxl with an illegal character or a live
    formula-injection payload any more than a fresh scan could."""
    rows: List[dict] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            row = {k: _csv_field(r, k) for k in DETAIL_FIELDS}
            for f_ in _SANITIZE_FIELDS:
                row[f_] = _sanitize_text(row.get(f_, ""))
            if row.get("root_escape") not in ("TRUE", "FALSE", "UNKNOWN"):
                logger.warning(f"Unrecognized root_escape value '{row.get('root_escape')}' for "
                                f"{row.get('server_ip')} in {csv_path}; defaulting to 'UNKNOWN'.")
                row["root_escape"] = "UNKNOWN"
            # classify_finding()/category_for_row() branch on scope_risk and
            # root_escape_likelihood just as much as root_escape -- a
            # hand-edited or stale value in either column that doesn't match
            # one of the canonical strings used to fail every `in (...)`
            # check silently and fall through to NFS_LOW with no warning at
            # all, quietly downgrading a row that may actually be Medium/
            # High/Critical. Validate both the same way root_escape already is.
            if row.get("scope_risk") not in ("CRITICAL", "HIGH", "MED", "LOW", "UNK"):
                logger.warning(f"Unrecognized scope_risk value '{row.get('scope_risk')}' for "
                                f"{row.get('server_ip')} in {csv_path}; defaulting to 'UNK'.")
                row["scope_risk"] = "UNK"
            if row.get("root_escape_likelihood") not in ("VERY_HIGH", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                logger.warning(f"Unrecognized root_escape_likelihood value "
                                f"'{row.get('root_escape_likelihood')}' for {row.get('server_ip')} "
                                f"in {csv_path}; defaulting to 'UNKNOWN'.")
                row["root_escape_likelihood"] = "UNKNOWN"
            rows.append(row)
    logger.info(f"Loaded {len(rows)} row(s) from {csv_path}")
    return rows


def rebuild_host_summary_from_detail(detail_rows: List[dict]) -> Dict[str, dict]:
    """Re-derive a per-host rollup (grain needed by the Overview sheet and
    row coloring) from detail rows alone -- used by --from-csv, where only
    the detail CSV is guaranteed to exist."""
    host_summary: Dict[str, dict] = {}
    for row in detail_rows:
        ip = row.get("server_ip", "")
        if not ip:
            continue
        s = host_summary.setdefault(ip, {
            "subnet": row.get("subnet", ""), "server_ip": ip,
            "hostname": row.get("hostname", ""), "dns_note": row.get("dns_note", ""),
            "exports_count": 0, "exports_sample": [],
            "highest_scope_risk": "UNK",
            "root_escape": row.get("root_escape", "UNKNOWN"),
            "nfs_versions": row.get("nfs_versions", ""),
            "root_escape_confidence": row.get("root_escape_confidence", "INFERRED"),
            "root_escape_evidence": row.get("root_escape_evidence", ""),
            "highest_root_escape_likelihood": "UNKNOWN",
            "verification_required": "NO",
            "risk_reason": row.get("risk_reason", ""), "why_flagged": row.get("why_flagged", ""),
            "showmount_status": "", "nse_status": "", "nxc_status": "",
            "_categories": [],
        })
        if row.get("export_path"):
            s["exports_count"] += 1
            if len(s["exports_sample"]) < 5:
                s["exports_sample"].append(row["export_path"])
        s["highest_scope_risk"] = max_severity(s["highest_scope_risk"], row.get("scope_risk", "UNK"))
        s["highest_root_escape_likelihood"] = max_likelihood(
            s["highest_root_escape_likelihood"], row.get("root_escape_likelihood", "UNKNOWN"))
        if row.get("root_escape") == "TRUE":
            s["root_escape"] = "TRUE"
            s["root_escape_confidence"] = "CONFIRMED"
            s["verification_required"] = "YES"
        elif row.get("verification_required") == "YES":
            s["verification_required"] = "YES"
        s["_categories"].append(category_for_row(row))

    for s in host_summary.values():
        s["exports_count"] = str(s["exports_count"])
        s["exports_sample"] = ";".join(s["exports_sample"])
        s["highest_category"] = worst_category(s.pop("_categories"))
    return host_summary


# =============================================================================
# XLSX
# =============================================================================

def compute_category_stats(detail_rows: List[dict]) -> Dict[str, int]:
    counts = {c: 0 for c in NFS_ORDER}
    for row in detail_rows:
        cat = category_for_row(row)
        counts[cat if cat in counts else NFS_UNKNOWN] += 1
    return counts


def build_workbook(detail_rows: List[dict], host_summary: Dict[str, dict],
                    networks: List[ipaddress.IPv4Network], nxc_available: Optional[bool]):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    def fill(hex_color: str):
        return PatternFill("solid", fgColor=hex_color)

    def thin_border():
        s = Side(style="thin", color="D5D8DC")
        return Border(left=s, right=s, top=s, bottom=s)

    wb = Workbook()

    # --- Overview sheet ---
    ov = wb.active
    ov.title = "Overview"
    ov.sheet_view.showGridLines = False
    ov.column_dimensions["A"].width = 34
    ov.column_dimensions["B"].width = 70
    ov.column_dimensions["C"].width = 14

    ov.append(["NFS no_root_squash / Anonymous-Access Assessment"])
    ov["A1"].font = Font(bold=True, size=14)
    ov.append([f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"])
    ov.append([f"Configured subnets in scope: {len(networks)}"])
    ov.append([f"Configured NFS port in scope: {NFS_PORT}"])
    if nxc_available is True:
        ov.append(["NetExec (nxc) was available: root_escape is CONFIRMED wherever nxc succeeded."])
    elif nxc_available is False:
        ov.append(["NetExec (nxc) was NOT available: root_escape is UNKNOWN for every host; "
                   "only the INFERRED root_escape_likelihood heuristic is reported."])
    else:
        ov.append(["NetExec (nxc) availability at scan time unknown (rebuilt via --from-csv); "
                   "see each row's root_escape_confidence column."])
    ov.append([])

    ov.append(["How to read this report"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    ov.append(["root_escape is either CONFIRMED (NetExec's `nxc nfs <ip>` actually tested it) or "
               "INFERRED (NetExec was unavailable, so only export-scope + NSE-enrichment heuristics "
               "could be used). A confirmed root escape always lands in the Critical bucket below, "
               "regardless of every other signal; everything else in this report is explicitly "
               "labeled as inferred, never silently presented as confirmed. See the category table "
               "and Methodology notes below."])
    ov.cell(row=ov.max_row, column=1).alignment = Alignment(wrap_text=True, vertical="top")
    ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
    ov.row_dimensions[ov.max_row].height = 70
    ov.append([])

    ov.append(["Category", "What it means"])
    for cell in ov[ov.max_row]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = fill("2C3E50")
    for category in NFS_ORDER:
        ov.append([f"{NFS_EMOJI[category]} {category}", NFS_DESCRIPTION[category]])
        row = ov.max_row
        ov.cell(row=row, column=1).fill = fill(NFS_FILL_HEX[category])
        ov.cell(row=row, column=1).font = Font(color=NFS_FONT_HEX[category], bold=True)
        ov.cell(row=row, column=2).alignment = Alignment(wrap_text=True, vertical="top")
        ov.row_dimensions[row].height = 75
    ov.append([])

    ov.append(["Methodology notes"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    for note in [
        "Phase 1 (masscan-preferred, nmap-fallback) finds every host with TCP/2049 open. Phase 2 "
        "runs, per host: hostname resolution, `showmount -e` export enumeration, read-only nmap "
        "NSE scripts (nfs-showmount, nfs-ls, nfs-statfs) to infer anonymous access, and `nxc nfs "
        "<ip>` (NetExec) for a CONFIRMED root-escape verdict when installed.",
        "CONFIRMED vs INFERRED: root_escape (TRUE/FALSE/UNKNOWN) and root_escape_confidence "
        "(CONFIRMED/INFERRED) come directly from NetExec. When nxc is unavailable or its per-host "
        "call fails, root_escape stays UNKNOWN and root_escape_confidence is INFERRED -- the only "
        "signal left is root_escape_likelihood, a heuristic built from export scope (scope_risk) "
        "plus NSE-observed listing/statfs access. A VERY_HIGH/HIGH likelihood is still a guess, "
        "never treated as equivalent to a confirmed True.",
        "A masscan/nmap hit on TCP/2049 only proves the port is open, not that real NFS is behind "
        "it -- a failed showmount is the main signal distinguishing those two cases, and both a "
        "showmount failure and a showmount success with zero parseable exports land in the "
        "'Unknown - Enumeration Incomplete' bucket for manual follow-up.",
        "No export is ever mounted by this tool, and no file on any target export is read, "
        "written, or created -- showmount and the three NSE scripts only query/list what the "
        "server already advertises.",
    ]:
        ov.append([note])
        ov.cell(row=ov.max_row, column=1).alignment = Alignment(wrap_text=True, vertical="top")
        ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
        ov.row_dimensions[ov.max_row].height = 60
    ov.append([])

    total = len(detail_rows)
    counts = compute_category_stats(detail_rows)
    ov.append(["Scan Summary"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    ov.append(["Total hosts with TCP/2049 open:", len(host_summary)])
    ov.append(["Total export rows (incl. enumeration-incomplete placeholders):", total])
    confirmed_true = sum(1 for r in host_summary.values() if r.get("root_escape") == "TRUE")
    ov.append(["Hosts with CONFIRMED root escape (no_root_squash=True):", confirmed_true])
    ov.append(["Category", "Count", "% of Total Rows"])
    for cell in ov[ov.max_row]:
        cell.font = Font(bold=True)
    for category in NFS_ORDER:
        pct = (counts[category] / total * 100.0) if total else 0.0
        ov.append([f"{NFS_EMOJI[category]} {category}", counts[category], round(pct, 1)])
        ov.cell(row=ov.max_row, column=1).fill = fill(NFS_FILL_HEX[category])
        ov.cell(row=ov.max_row, column=3).number_format = "0.0"
    ov.append([])

    # Subnet breakdown
    subnet_counts: Dict[str, int] = {}
    for row in detail_rows:
        key = row.get("subnet", "UNKNOWN") or "UNKNOWN"
        subnet_counts[key] = subnet_counts.get(key, 0) + 1
    ov.append(["Subnet Breakdown (by export row)"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    for subnet, count in sorted(subnet_counts.items()):
        ov.append([subnet, count])

    # --- Scan Results sheet ---
    wr = wb.create_sheet("Scan Results")
    wr.sheet_view.showGridLines = False
    wr.freeze_panes = "A2"

    headers = DETAIL_FIELDS
    widths = {
        "subnet": 18, "server_ip": 16, "hostname": 26, "dns_note": 12,
        "export_path": 34, "allowed_clients": 28,
        "scope_risk": 12, "listing_access": 12, "statfs_access": 12,
        "root_escape": 12, "nfs_versions": 14, "root_escape_confidence": 16,
        "root_escape_evidence": 36,
        "root_escape_likelihood": 16, "root_escape_basis": 36,
        "verification_required": 14,
        "risk_reason": 40, "why_flagged": 50,
        "note": 24,
    }
    wrap_cols = {"export_path", "allowed_clients", "risk_reason", "why_flagged", "root_escape_evidence"}

    for col_idx, col_name in enumerate(headers, start=1):
        c = wr.cell(row=1, column=col_idx, value=col_name)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = fill("2C3E50")
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = thin_border()
        wr.column_dimensions[get_column_letter(col_idx)].width = widths.get(col_name, 16)
    wr.row_dimensions[1].height = 22

    cat_col_idx = len(headers) + 1
    cat_header = wr.cell(row=1, column=cat_col_idx, value="category")
    cat_header.font = Font(bold=True, color="FFFFFF")
    cat_header.fill = fill("2C3E50")
    cat_header.alignment = Alignment(horizontal="center", vertical="center")
    cat_header.border = thin_border()
    wr.column_dimensions[get_column_letter(cat_col_idx)].width = 42

    for row_idx, row in enumerate(detail_rows, start=2):
        cat = category_for_row(row)
        for col_idx, key in enumerate(headers, start=1):
            val = row.get(key, "")
            if key in _SANITIZE_FIELDS:
                val = _neutralize_formula(val)
            c = wr.cell(row=row_idx, column=col_idx, value=val)
            c.border = thin_border()
            c.alignment = Alignment(vertical="top", wrap_text=(key in wrap_cols), horizontal="left")
            c.fill = fill(NFS_FILL_HEX[cat])
        cat_cell = wr.cell(row=row_idx, column=cat_col_idx, value=f"{NFS_EMOJI[cat]} {cat}")
        cat_cell.fill = fill(NFS_FILL_HEX[cat])
        cat_cell.font = Font(color=NFS_FONT_HEX[cat], bold=True)
        cat_cell.border = thin_border()
        wr.row_dimensions[row_idx].height = 40

    if detail_rows:
        wr.auto_filter.ref = f"A1:{get_column_letter(cat_col_idx)}{len(detail_rows) + 1}"

    return wb


def write_xlsx_report(detail_rows: List[dict], host_summary: Dict[str, dict],
                       networks: List[ipaddress.IPv4Network], nxc_available: Optional[bool],
                       path: str, logger: logging.Logger) -> None:
    try:
        wb = build_workbook(detail_rows, host_summary, networks, nxc_available)
    except ImportError:
        logger.warning("openpyxl not installed - skipping .xlsx generation. "
                        "Install with: pip install openpyxl")
        return
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to build XLSX workbook: {exc}")
        return
    try:
        wb.save(path)
        logger.info(f"XLSX report written to {path} ({len(detail_rows)} row(s), "
                    f"{len(host_summary)} host(s))")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to write XLSX report to {path}: {exc}")


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized internal NFS no_root_squash / anonymous-access assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--masscan-rate", type=int, default=DEFAULT_MASSCAN_RATE)
    parser.add_argument("--masscan-retries", type=int, default=DEFAULT_MASSCAN_RETRIES)
    parser.add_argument("--nmap-timing", type=str, default=DEFAULT_NMAP_TIMING,
                         help="nmap fallback timing template, e.g. T4 (no leading '-')")
    parser.add_argument("--nmap-min-rate", type=int, default=DEFAULT_NMAP_MIN_RATE)
    parser.add_argument("--showmount-timeout", type=int, default=DEFAULT_SHOWMOUNT_TIMEOUT)
    parser.add_argument("--nse-timeout", type=int, default=DEFAULT_NSE_TIMEOUT)
    parser.add_argument("--nxc-timeout", type=int, default=DEFAULT_NXC_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                         help="Bounded retry of showmount/NSE/nxc on a timeout/connection-style "
                              "failure only -- not retried for a deterministic non-error result")
    parser.add_argument("--output-dir", type=str, default=SCRIPT_DIR)
    parser.add_argument("--masscan-path", type=str, default="masscan")
    parser.add_argument("--nmap-path", type=str, default="nmap")
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--skip-masscan", action="store_true")
    parser.add_argument("--prefer-nmap", action="store_true",
                         help="Force nmap-only discovery even if masscan is present on PATH "
                              "(e.g. an engagement where only nmap connect/SYN scanning is "
                              "authorized). Restores the old script's PREFER_MASSCAN=False option.")
    parser.add_argument("--masscan-output-file", type=str, default=None)
    parser.add_argument("--no-xlsx", action="store_true")
    parser.add_argument("--from-csv", metavar="FILE",
                         help="Skip scanning entirely (no external tools needed); rebuild the "
                              ".xlsx from a previously-written detail CSV")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    date_suffix = datetime.now().strftime("%m_%Y")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create output directory '{args.output_dir}': {exc}", file=sys.stderr)
        return 1

    log_path = os.path.join(args.output_dir, f"nfs_no_root_squash_{date_suffix}.log")
    detail_csv = os.path.join(args.output_dir, f"nfs_exports_detail_{date_suffix}.csv")
    summary_csv = os.path.join(args.output_dir, f"nfs_hosts_summary_{date_suffix}.csv")
    rootescape_csv = os.path.join(args.output_dir, f"nfs_root_escape_TRUE_{date_suffix}.csv")
    xlsx_path = os.path.join(args.output_dir, f"nfs_no_root_squash_{date_suffix}.xlsx")

    try:
        logger = setup_logging(log_path)
    except OSError as exc:
        print(f"ERROR: Could not open log file '{log_path}': {exc}", file=sys.stderr)
        return 1

    # Report filenames use a month+year suffix (not day, unlike the sibling
    # scripts) -- a deliberate choice to support recurring monthly
    # engagements, but it means a second run in the same calendar month
    # overwrites the first run's reports outright. That's fine when it's
    # intentional (a deliberate monthly re-check); it's a silent evidence
    # loss when it's not. This can't be more than a warning (still must
    # proceed non-interactively), but it must not be silent.
    for existing_path in (detail_csv, summary_csv, rootescape_csv, xlsx_path):
        if os.path.exists(existing_path):
            logger.warning(f"Overwriting existing report from this month: {existing_path}")

    networks = validate_subnets(SUBNETS, logger)

    # --from-csv rebuilds the workbook with ZERO external tool calls -- this
    # is the one path where nmap/showmount/masscan/nxc being absent (or even
    # this not being Kali/Linux at all) must not matter.
    if args.from_csv:
        try:
            detail_rows = read_rows_from_csv(args.from_csv, logger)
        except OSError as exc:
            logger.error(f"Could not read --from-csv file '{args.from_csv}': {exc}")
            return 1
        except (csv.Error, UnicodeDecodeError) as exc:
            logger.error(f"--from-csv file '{args.from_csv}' is not a valid UTF-8 CSV: {exc}")
            return 1
        host_summary = rebuild_host_summary_from_detail(detail_rows)
        if not args.no_xlsx:
            write_xlsx_report(detail_rows, host_summary, networks, None, xlsx_path, logger)
        return 0

    stop_event = threading.Event()

    def handle_sigint(signum, frame):  # noqa: ANN001
        if stop_event.is_set():
            logger.warning("Second interrupt received, forcing exit.")
            sys.exit(130)
        logger.warning("Ctrl+C received - finishing current work and writing "
                        "partial reports. Press Ctrl+C again to force exit.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    logger.info("=" * 70)
    logger.info("AUTHORIZED NFS NO_ROOT_SQUASH / ANONYMOUS-ACCESS ASSESSMENT")
    logger.info("=" * 70)
    logger.info("Configured subnets in scope:")
    for s in SUBNETS:
        logger.info(f"  - {s}")
    logger.info(f"Workers: {args.workers} | Retries: {args.retries} | "
                f"showmount timeout: {args.showmount_timeout}s | NSE timeout: {args.nse_timeout}s | "
                f"nxc timeout: {args.nxc_timeout}s")

    if not networks:
        logger.error("No valid subnets configured. Exiting.")
        return 1

    # Required tools -- checked here, not at import time (see module docstring
    # / README for why: --help and --from-csv must both work with none of
    # these installed).
    resolved_nmap = check_external_tool(args.nmap_path)
    if resolved_nmap is None:
        logger.error(f"Required tool '{args.nmap_path}' was not found on PATH. nmap is required "
                      f"for both the NSE enrichment step and the discovery fallback.")
        return 1
    args.nmap_path = resolved_nmap

    resolved_showmount = check_external_tool("showmount")
    if resolved_showmount is None:
        logger.error("Required tool 'showmount' was not found on PATH (nfs-common / nfs-utils).")
        return 1

    masscan_path = check_external_tool(args.masscan_path)
    if args.prefer_nmap:
        # Restores the old script's module-level PREFER_MASSCAN=False
        # override: force nmap-only discovery even though masscan is
        # present (e.g. an engagement where only nmap connect/SYN scanning
        # is authorized). --skip-masscan is not a substitute for this --
        # it requires a pre-existing --masscan-output-file and skips live
        # scanning entirely rather than substituting live nmap discovery.
        if masscan_path:
            logger.info("--prefer-nmap set; ignoring masscan on PATH and using the nmap "
                         "discovery fallback instead.")
        masscan_path = None
    if args.skip_masscan:
        if not args.masscan_output_file or not os.path.exists(args.masscan_output_file):
            logger.error("--skip-masscan requires a valid --masscan-output-file.")
            return 1
    elif masscan_path is None and not args.prefer_nmap:
        logger.info(f"'{args.masscan_path}' not found on PATH; discovery will use the nmap "
                     f"fallback (install masscan for much faster large-range scans).")

    nxc_path = shutil.which("nxc") or shutil.which("netexec")
    if nxc_path:
        logger.info(f"NetExec found ({os.path.basename(nxc_path)}); root_escape will be "
                     f"CONFIRMED via `nxc nfs <ip>`.")
    else:
        logger.warning("nxc/netexec not found on PATH; root_escape will be UNKNOWN for every "
                        "host (only the INFERRED root_escape_likelihood will be reported). "
                        "Install NetExec for True/False verdicts.")
    dig_path = shutil.which("dig")
    host_path = shutil.which("host")

    # Phase 1
    if args.skip_masscan:
        raw_records, _ = parse_masscan_list_output(args.masscan_output_file, 0)
        hosts_ips = sorted({ip for ip, port, _ in raw_records if port == NFS_PORT})
        logger.info(f"Loaded {len(hosts_ips)} host(s) from --masscan-output-file.")
    else:
        try:
            hosts_ips = discover_nfs_hosts(masscan_path, args.nmap_path, args, args.output_dir,
                                            date_suffix, logger, stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Phase 1 discovery failed unexpectedly: {exc}")
            hosts_ips = []

    logger.info(f"Phase 1 complete: {len(hosts_ips)} host(s) with TCP/{NFS_PORT} open")
    if not hosts_ips:
        logger.info("No NFS hosts found. Exiting.")
        return 130 if stop_event.is_set() else 0

    discovered = [DiscoveredHost(ip=ip, subnet=subnet_for_ip(ip, networks)) for ip in hosts_ips]

    detail_rows: List[dict] = []
    host_summary: Dict[str, dict] = {}
    if discovered:
        # Deliberately not gated on "and not stop_event.is_set()" - same
        # reasoning as the sibling scripts: a Ctrl+C during Phase 1 can set
        # stop_event while discovered is already non-empty (Phase 1 returns
        # partial results by design), and run_phase2() itself already honors
        # stop_event correctly (cancels remaining futures, returns whatever
        # completed). Gating here too meant an interrupt during/just-after
        # Phase 1 skipped Phase 2 entirely and wrote an empty report,
        # contradicting this script's own "finishing current work and
        # writing partial reports" SIGINT message.
        detail_rows, host_summary = run_phase2(discovered, args, logger, stop_event,
                                                resolved_showmount, args.nmap_path, nxc_path,
                                                dig_path, host_path)
    else:
        logger.info("No hosts to audit in Phase 2; skipping.")

    write_detail_csv(detail_rows, detail_csv, logger)
    write_summary_csv(host_summary, summary_csv, logger)
    confirmed_count = write_rootescape_csv(host_summary, rootescape_csv, logger)
    if not args.no_xlsx:
        write_xlsx_report(detail_rows, host_summary, networks, nxc_path is not None, xlsx_path, logger)

    logger.info("=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  NFS hosts found: {len(host_summary)} | Export rows: {len(detail_rows)} | "
                f"Confirmed root-escape hosts: {confirmed_count}")
    if nxc_path:
        for ip in sorted(ip for ip, r in host_summary.items() if r.get("root_escape") == "TRUE"):
            logger.info(f"    - {ip} ({host_summary[ip].get('hostname', '')})")
    else:
        logger.warning("  nxc/netexec was not available - root_escape could not be confirmed; "
                        "the root-escape CSV is empty.")
    logger.info("=" * 70)
    logger.info(f"Reports written to: {os.path.abspath(args.output_dir)}")

    if stop_event.is_set():
        logger.warning("Scan was interrupted by user; reports reflect partial results.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
