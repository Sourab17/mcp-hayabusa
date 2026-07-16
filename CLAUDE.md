# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This project is an MCP (Model Context Protocol) server that wraps
[Hayabusa](https://github.com/Yamato-Security/hayabusa), the Windows event log fast forensics
timeline generator and threat hunting tool, to expose EVTX analysis over MCP.

### Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

### Stack

- Python, using the `mcp` library for the server implementation
- Hayabusa CLI (installed locally) invoked as a subprocess

## Status

This repository currently has no commits or source files yet — only this planning document.
There is no build configuration or dependency manifest to derive commands from.

## Next steps for future instances

Once source files exist, replace the "Status" and "Next steps" sections with real guidance
covering:
- Package manager and project layout (check for `pyproject.toml`, `requirements.txt`, etc.)
- Build, lint, and test commands (including how to run a single test)
- MCP server entry point and how the `scan_evtx` tool is registered
- How the server locates/invokes the Hayabusa binary, and what output format/flags it expects
  (e.g. Hayabusa's JSON/JSONL output) to translate into the tool's structured JSON response
- How severity-level filtering is implemented (mapping to Hayabusa's own level flags vs.
  post-filtering output)
- Error handling conventions (e.g. missing EVTX file, Hayabusa not installed, malformed output)
- Any configuration required to run the server locally (e.g. path to the Hayabusa binary, sample
  EVTX files for testing)
