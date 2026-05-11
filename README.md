# Ravynel Security Launch Guide

Ravynel Security is an enterprise-style network detection and response platform for live packet capture, protocol analysis, host/session visibility, alert triage, asset baselining, and PDF investigation reporting.

Developed by: [HeliSudani](https://helisudani0.github.io/Heli_Sudani-Portfolio/)

## Public Launch Model

| Surface | Hosted on | Purpose |
| --- | --- | --- |
| Product site | GitHub Pages | Public overview, documentation, release notes, support, and download links |
| Download assets | GitHub Releases | Windows launcher ZIP, Linux bootstrap, Kubernetes manifest, checksums |
| Ravynel app | User machine / internal network | Local analyst console for capture, detections, assets, sessions, reports, and settings |

The product site does not run capture. Users download a release package, launch the desktop GUI, and the GUI starts the local analyzer.

## Build Release Downloads

```powershell
python scripts\package_release.py
```

This creates:

```text
dist/Ravynel-Windows-Launcher.zip
dist/ravynel-sensor-linux-install.sh
dist/ravynel-kubernetes-control-plane.yaml
dist/checksums.txt
```

The Windows ZIP includes the GUI launcher, analyzer engine, profiles, feeds, requirements, and first-run setup notes.

## Windows First Run

1. Install Python 3.12+.
2. Install Npcap for live packet capture.
3. Extract `Ravynel-Windows-Launcher.zip`.
4. Run `python -m pip install -r requirements.txt` inside the extracted folder.
5. Double-click `Ravynel-Launch.pyw`.
6. Press Start in the GUI.

If packet capture is blocked, run the launcher as Administrator. For full LAN visibility, deploy Ravynel at a gateway, SPAN/TAP mirror, or distributed sensor. A normal laptop adapter only sees traffic visible to that adapter.

## Local Development

Start the app:

```powershell
.\scripts\start-ravynel.ps1
```

Start the product site:

```powershell
npm run dev:site
```

## Validation

```powershell
python scripts\package_release.py
npm run typecheck
npm run build:site
cargo test
$env:GOCACHE=(Resolve-Path .).Path + '\.tmp_go_cache'; go test .\services\control-plane\...
```

## Security Notes

- Verify `checksums.txt` before distributing release assets internally.
- Unsigned script ZIPs may trigger Windows SmartScreen. Enterprise rollout should use signed EXE/MSI packages.
- Scan or capture only networks you own or are explicitly authorized to assess.
