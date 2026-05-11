# Ravynel Product Architecture

Ravynel separates public product education from installed security operations.

## Public Website

`apps/marketing` is a Next.js marketing and documentation site. It does not run scans, expose backend controls, or offer raw source downloads. It presents product overview, documentation, onboarding, installer downloads, release notes, and support.

## Installed Operator Application

`analyzer/app_ui.py` renders the dedicated local SOC console served by the Python analyzer at `/app`. It is the only app frontend; `apps/marketing` is the separate public product site.

## Control Plane

`services/control-plane` is the Go backend using Gin for HTTP APIs and gRPC for agent communications. It owns scan orchestration, distributed agent management, and operational state.

## Agent Core

`engines/agent-core` is the Rust foundation for safe, high-performance network range expansion and future capture/discovery workloads.

## Infrastructure

PostgreSQL stores durable events and hunt history. Redis supports queues, ephemeral scan coordination, and websocket fan-out. Docker, Kubernetes, and Nginx assets live under `infra`.

