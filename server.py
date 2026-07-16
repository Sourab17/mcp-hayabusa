#!/usr/bin/env python3
"""MCP server that wraps Hayabusa for EVTX analysis."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

HAYABUSA_DIR = Path(__file__).resolve().parent / "hayabusa"
HAYABUSA_BIN = HAYABUSA_DIR / ("hayabusa.exe" if sys.platform == "win32" else "hayabusa")
RULES_DIR = HAYABUSA_DIR / "rules"

SEVERITY_LEVELS = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Hayabusa abbreviates some Level values (e.g. "med", "info") unless run with
# -b/--disable-abbreviations. We pass -b below, but keep these aliases as a
# defensive fallback so filtering still works correctly if that ever changes.
LEVEL_ALIASES = {
    "info": "informational",
    "med": "medium",
    "crit": "critical",
}

SCAN_TIMEOUT_SECONDS = 600

# Fields kept for output_format="full" vs the trimmed "summary" view.
SUMMARY_FIELDS = (
    "Timestamp",
    "RuleTitle",
    "Level",
    "Computer",
    "Channel",
    "EventID",
    "RecordID",
    "RuleID",
)


def _error(message: str) -> str:
    return json.dumps({"success": False, "error": message}, indent=2)


def _summarize(finding: dict) -> dict:
    return {key: finding[key] for key in SUMMARY_FIELDS if key in finding}


@mcp.tool()
def scan_evtx(
    evtx_path: str,
    min_severity: str = "informational",
    rule_filter: str = "",
    output_format: str = "summary",
    max_results: int = 0,
) -> str:
    """Scan a single EVTX file with Hayabusa and return matching detections.

    Args:
        evtx_path: Path to the .evtx file to scan.
        min_severity: Minimum severity level to include in the results
            (informational, low, medium, high, critical). Defaults to
            "informational", which includes every detection.
        rule_filter: Only include findings whose rule title contains this
            string (case-insensitive). Empty string (default) includes all.
        output_format: "summary" (default) returns a trimmed set of fields
            per finding; "full" returns every field Hayabusa produced,
            including Details and ExtraFieldInfo.
        max_results: Maximum number of findings to return. 0 (default)
            means no limit. Findings are truncated after severity/rule
            filtering, keeping the earliest matches.
    """
    normalized_severity = min_severity.strip().lower()
    if normalized_severity not in SEVERITY_LEVELS:
        return _error(
            f"Invalid min_severity {min_severity!r}. "
            "Must be one of: informational, low, medium, high, critical."
        )
    min_ordinal = SEVERITY_LEVELS[normalized_severity]

    normalized_format = output_format.strip().lower()
    if normalized_format not in ("summary", "full"):
        return _error(
            f"Invalid output_format {output_format!r}. Must be 'summary' or 'full'."
        )

    if max_results < 0:
        return _error(f"Invalid max_results {max_results!r}. Must be >= 0.")

    normalized_rule_filter = rule_filter.strip().lower()

    path = Path(evtx_path)
    if not path.exists():
        return _error(f"EVTX file not found: {evtx_path}")
    if not path.is_file():
        return _error(f"Not a file: {evtx_path}")

    if not HAYABUSA_BIN.exists():
        return _error(
            f"Hayabusa binary not found at {HAYABUSA_BIN}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    with tempfile.TemporaryDirectory(prefix="hayabusa-scan-") as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        command = [
            str(HAYABUSA_BIN),
            "json-timeline",
            "-f", str(path),
            "-o", str(output_path),
            "-L",  # JSONL output: one finding per line, easy to parse
            "-w",  # no-wizard: don't prompt interactively
            "-q",  # quiet: suppress the launch banner
            "-N",  # skip the results summary table
            "-K",  # no color codes in stdout/stderr
            "-C",  # clobber: allow overwriting the output file
            "-b",  # disable abbreviations, so Level is spelled out in full
        ]

        try:
            proc = subprocess.run(
                command,
                cwd=HAYABUSA_DIR,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return _error(f"Hayabusa binary not found or not executable at {HAYABUSA_BIN}.")
        except subprocess.TimeoutExpired:
            return _error(f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS} seconds.")
        except OSError as exc:
            return _error(f"Failed to run Hayabusa: {exc}")

        if proc.returncode != 0:
            return _error(
                f"Hayabusa scan failed (exit code {proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )

        if not output_path.exists():
            return _error(
                "Hayabusa did not produce an output file. "
                f"stdout: {proc.stdout.strip()!r} stderr: {proc.stderr.strip()!r}"
            )

        findings = []
        with output_path.open(encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError as exc:
                    return _error(f"Failed to parse Hayabusa output line {line_num}: {exc}")

                level = str(finding.get("Level", "")).strip().lower()
                level = LEVEL_ALIASES.get(level, level)
                if SEVERITY_LEVELS.get(level, 0) < min_ordinal:
                    continue

                if normalized_rule_filter and normalized_rule_filter not in str(
                    finding.get("RuleTitle", "")
                ).lower():
                    continue

                findings.append(finding)

    total_findings = len(findings)
    if max_results:
        findings = findings[:max_results]

    if normalized_format == "summary":
        findings = [_summarize(finding) for finding in findings]

    result = {
        "success": True,
        "evtx_path": str(path),
        "min_severity": normalized_severity,
        "rule_filter": rule_filter,
        "output_format": normalized_format,
        "total_findings": total_findings,
        "returned_findings": len(findings),
        "findings": findings,
    }
    return json.dumps(result, indent=2)


_rules_cache: list[dict] | None = None


def _load_rules() -> list[dict]:
    """Parse every rule YAML under RULES_DIR into a summary dict.

    Rule files are static assets bundled with the Hayabusa install, so the
    parsed result is cached for the life of the process (parsing ~5000 files
    takes several seconds).
    """
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    rules = []
    for rule_path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            with rule_path.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "title" not in data:
            continue

        logsource = data.get("logsource") or {}
        rules.append({
            "id": data.get("id", ""),
            "title": data.get("title", ""),
            "level": str(data.get("level", "")).strip().lower(),
            "status": data.get("status", ""),
            "description": data.get("description") or "",
            "tags": data.get("tags") or [],
            "logsource": {
                key: logsource[key]
                for key in ("product", "category", "service")
                if key in logsource
            },
            "path": rule_path.relative_to(RULES_DIR).as_posix(),
        })

    _rules_cache = rules
    return rules


def _rule_matches(rule: dict, keyword: str) -> bool:
    haystacks = [rule["title"], rule["description"], rule["id"], " ".join(rule["tags"])]
    return any(keyword in haystack.lower() for haystack in haystacks)


@mcp.tool()
def get_hayabusa_rules(keyword: str = "", max_results: int = 100) -> str:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Useful for understanding what rules exist (and what they detect) before
    running scan_evtx, e.g. to pick a value for scan_evtx's rule_filter.

    Args:
        keyword: Only include rules whose title, description, tags, or rule
            ID contain this string (case-insensitive). Empty string
            (default) includes all rules.
        max_results: Maximum number of rules to return. Defaults to 100
            (there are several thousand rules in total); use 0 for no limit.
            Rules are truncated after keyword filtering.
    """
    if not RULES_DIR.exists():
        return _error(
            f"Hayabusa rules directory not found at {RULES_DIR}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    if max_results < 0:
        return _error(f"Invalid max_results {max_results!r}. Must be >= 0.")

    all_rules = _load_rules()

    normalized_keyword = keyword.strip().lower()
    if normalized_keyword:
        matched = [rule for rule in all_rules if _rule_matches(rule, normalized_keyword)]
    else:
        matched = all_rules

    total_matched = len(matched)
    if max_results:
        matched = matched[:max_results]

    result = {
        "success": True,
        "keyword": keyword,
        "total_rules": len(all_rules),
        "total_matched": total_matched,
        "returned_count": len(matched),
        "rules": matched,
    }
    return json.dumps(result, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
