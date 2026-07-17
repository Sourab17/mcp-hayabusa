# mcp-hayabusa

## Project layout

- `server.py` — the MCP server entry point; both tools are defined here
- `requirements.txt` — Python dependencies (`mcp`, `pyyaml`)
- `hayabusa/` — the Hayabusa binary, rule set, and config, installed by
  `scripts/download_hayabusa.py` (gitignored; not checked in)
- `scripts/download_hayabusa.py` — downloads the latest Hayabusa release for the current
  platform and extracts it into `hayabusa/`
- `samples/` — sample EVTX files for manual testing (e.g. `sysmon_lsass_mimikatz.evtx`)
- `.mcp.json` — registers the `hayabusa` MCP server (`python server.py`) for this project
- `.claude/settings.json` — allowlists (`enabledMcpjsonServers`) the server defined in
  `.mcp.json` so Claude Code doesn't prompt for approval on every session

## Setup and running locally

```
pip install -r requirements.txt
python scripts/download_hayabusa.py   # installs hayabusa/ (binary + rules), if not present
```

The server is launched by Claude Code via `.mcp.json` (`python server.py`, stdio transport) —
there's no separate "start the server" step when working through Claude Code. To run/debug it
standalone, `python server.py` starts it directly.

There is no formal test suite (no pytest config) — verify behavior by calling the tools directly,
e.g.:

```
python -c "from server import scan_evtx; print(scan_evtx('samples/sysmon_lsass_mimikatz.evtx'))"
python -c "from server import get_hayabusa_rules; print(get_hayabusa_rules(keyword='mimikatz'))"
```

Note: an already-running MCP connection does not pick up `server.py` edits — reconnect/restart
the MCP server (e.g. `/mcp` reconnect in Claude Code) to see code changes reflected in tool calls.

## MCP tools

### `scan_evtx(evtx_path, min_severity="informational", rule_filter="", output_format="summary", max_results=0)`

Runs `hayabusa json-timeline` against a single EVTX file and returns structured JSON detections.

- Invokes the binary with `-L` (JSONL output), `-w` (no interactive wizard), `-q`/`-N`/`-K`
  (quiet, no summary table, no color codes), `-C` (clobber output file), `-b` (disable Level
  abbreviations) — output is written to a temp file and parsed line by line.
- `min_severity` is **post-filtered** in Python against `SEVERITY_LEVELS`
  (informational < low < medium < high < critical), not passed to Hayabusa as a CLI flag.
  `LEVEL_ALIASES` maps abbreviated Level values back to full names as a defensive fallback.
- `rule_filter` is a case-insensitive substring match against each finding's `RuleTitle`.
- `output_format="summary"` (default) trims each finding to `SUMMARY_FIELDS` (Timestamp,
  RuleTitle, Level, Computer, Channel, EventID, RecordID, RuleID); `"full"` returns every field
  Hayabusa produced, including `Details` and `ExtraFieldInfo`.
- `max_results` truncates the returned list after severity/rule filtering; the response's
  `total_findings` still reports the full filtered count so callers can tell when results were
  capped.
- Scans time out after `SCAN_TIMEOUT_SECONDS` (600s).

### `get_hayabusa_rules(keyword="", max_results=100)`

Lists Hayabusa's bundled Sigma/built-in detection rules by parsing every YAML file under
`hayabusa/rules/**/*.yml` (~5000 files). Useful for discovering rule titles (to feed into
`scan_evtx`'s `rule_filter`) or understanding what a rule detects before scanning.

- Parsed rule metadata (`id`, `title`, `level`, `status`, `description`, `tags`, `logsource`,
  `path`) is cached in `_rules_cache` for the life of the process — the first call takes several
  seconds (full YAML parse), subsequent calls are near-instant. The cache is invalidated only by
  restarting the server.
- `keyword` is a case-insensitive substring match against title, description, rule ID, and tags.
- `max_results` defaults to 100 (there are thousands of rules); `0` means no limit. Response
  includes `total_rules`, `total_matched`, and `returned_count`.
- Malformed rule YAML, or files without a `title` field, are silently skipped.

## Error handling conventions

Both tools return `_error(message)` — `{"success": false, "error": "..."}` — rather than raising,
for: invalid enum/range arguments (`min_severity`, `output_format`, negative `max_results`),
missing/non-file `evtx_path`, missing Hayabusa binary or rules directory, non-zero Hayabusa exit
code, missing output file, malformed JSONL output line, subprocess timeout, and `OSError`/
`FileNotFoundError` when invoking the binary. Successful responses always include `"success":
true`.
