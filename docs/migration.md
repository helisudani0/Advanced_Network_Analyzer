# Ravynel Migration Notes

## Why Rust and Go

The original Python platform proved the detection feature set quickly. Ravynel now moves toward a production architecture with Rust and Go as the primary runtime stack.

Rust owns packet-adjacent and agent-adjacent logic because it gives strong memory safety, predictable binaries, and better control over low-level parsing.

Go owns the API, orchestration, and product workflows because it is excellent for concurrent services, HTTP APIs, worker coordination, and simple deployment.

## Current Migration State

Completed in this repository:

- New Ravynel brand and logo.
- Public website separated from the authenticated console.
- Go API and orchestration service.
- Authenticated SaaS-style console.
- Rust packet-event detection core.
- Rust remote sensor foundation.
- Workspace structure for Go and Rust builds.
- PDF report generation from the Go service without Python dependencies.

Compatibility retained:

- Existing Python analyzer remains in place as the legacy capture and feature-rich detection adapter while Go/Rust parity is expanded.

## Next Engineering Cutover

- Move protocol parsers from Python into `engines/agent-core`.
- Add Rust native capture adapter backed by Npcap/libpcap.
- Add Go PostgreSQL event store and long-term hunt APIs.
- Move report content generation fully into Go and use Rust findings as detection input.
- Deprecate Python CLI once parity is proven by fixtures and replay tests.

