# Ravynel Architecture

Ravynel NDR is organized as a product, not a single script. Public education, operator workflows, high-throughput services, and packet-level logic live in separate boundaries.

## Service Boundaries

```text
apps/marketing          Public product website: overview, features, docs, downloads, onboarding
apps/console          Authenticated analyst console and operational workflows
services/control-plane  Go API, orchestration layer, auth, reports, runtime state
engines/agent-core  Rust detection core for packet-event analysis
analyzer/sensor.py Rust remote sensor foundation for forwarding raw packet frames
brand                 Logo, naming, color, and identity assets
configs               Deployment-ready example configuration
legacy Python files   Compatibility adapter while Go/Rust parity is completed
```

## Runtime Flow

```text
Local adapters / PCAP / Remote sensors
        |
        v
Rust sensor and Rust packet-event core
        |
        v
Go orchestration API
        |
        +--> authenticated console
        +--> reporting/export workflows
        +--> future database/storage adapters
```

## Technology Ownership

Rust is used where memory safety, low-level packet handling, and agent hardening matter most:

- packet-event detection core
- remote sensor foundation
- future native capture adapters
- future FFI/WASM detector modules

Go is used where concurrency, service operations, API ergonomics, and packaging matter most:

- authenticated console backend
- runtime orchestration
- report/export workflows
- remote ingest endpoints
- worker coordination

Python remains only as a legacy compatibility adapter for the previously built analyzer until every capture and protocol parser path reaches Go/Rust parity.

## Security Posture

- Console access is authenticated with a token supplied by `Ravynel_CONSOLE_TOKEN`.
- The default development token is `Ravynel-local` and must not be used for production.
- The Go API applies baseline browser hardening headers.
- The Rust sensor is passive and only forwards observed bytes to the configured collector.
- Ravynel does not inject packets or block traffic automatically.

## Production Roadmap

- Replace local JSON state with PostgreSQL-backed event storage in the Go service.
- Add native Rust/Npcap adapter for Windows and libpcap adapter for Linux/macOS.
- Replace the compatibility Python capture adapter once Rust capture parity is complete.
- Add signed desktop packages and installer update channels.
- Add OIDC/SAML authentication for enterprise deployments.

