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

