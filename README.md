# Ravynel Security Launch Guide

Ravynel Security is a live network threat detection platform for packet capture, protocol analysis, host/session visibility, alert triage, asset baselining, and PDF investigation reporting.

Developed by: [HeliSudani](https://helisudani0.github.io/Heli_Sudani-Portfolio/)

## Product Surfaces

| Surface | Purpose | Default URL |
| --- | --- | --- |
| Product site | Public overview, docs, release notes, support, and downloads | `http://localhost:3000` during website development |
| Ravynel app | Installed/local analyst console for live capture, detections, assets, reports, and settings | Opened automatically by the launcher |

The product site is not required to use the app. Downloaded users launch the Ravynel app directly.

## Start The App

```powershell
.\scripts\start-ravynel.ps1
```

The launcher chooses a free local API port, starts the analyzer in the background, waits for it to become ready, and opens the clean app GUI in your browser. Logs are written to `logs/app.out.log` and `logs/app.err.log`.

If you need to see logs immediately:

```powershell
.\scripts\start-ravynel.ps1 -ShowLogs
```

Manual terminal launch:

```powershell
python app.py dashboard
```

## Start The Product Site For Development

```powershell
npm run dev:site
```

Open:

```text
http://localhost:3000
```

## Live Packet Capture

You do not type an IP range for live packet capture. Ravynel monitors the selected local adapter or the default packet-capture adapter.

Examples:

```powershell
python app.py dashboard
python app.py dashboard --iface Ethernet
python app.py dashboard --iface Wi-Fi --bpf-filter "tcp or udp"
```

A normal laptop Wi-Fi/Ethernet adapter sees traffic visible to that adapter. For full enterprise LAN visibility, deploy a gateway sensor, SPAN/TAP capture point, or distributed Ravynel sensors.

## Reports

Reports are generated from real captured or replayed telemetry and saved as PDFs in `reports/`.

```powershell
python app.py report
```

## Validation

```powershell
npm run typecheck
npm run build:site
cargo test
$env:GOCACHE=(Resolve-Path .).Path + '\.tmp_go_cache'; go test .\services\control-plane\...
```

## Notes

- Ravynel displays observed telemetry only.
- Normal traffic may produce packets, sessions, hosts, and assets without producing alerts.
- Scan or capture only networks you own or are explicitly authorized to assess.
