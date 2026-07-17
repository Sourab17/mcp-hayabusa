# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This project is an MCP (Model Context Protocol) server that wraps
[Hayabusa](https://github.com/Yamato-Security/hayabusa), the Windows event log fast forensics
timeline generator and threat hunting tool, to expose EVTX analysis over MCP.

### Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files and returns structured JSON,
  filterable by severity, rule title, output verbosity, and result count
- Expose a `get_hayabusa_rules` tool that lists Hayabusa's bundled detection rules, filterable
  by keyword, so a caller can discover relevant rules before scanning
- Handle errors gracefully

### Stack

- Python, using the `mcp` library (`FastMCP`) for the server implementation
- Hayabusa CLI (installed locally under `hayabusa/`) invoked as a subprocess
- PyYAML, for parsing Hayabusa's rule files

=======
