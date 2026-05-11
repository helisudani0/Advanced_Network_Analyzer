from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys
import threading
import time
import webbrowser

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer import PlatformConfig, ThreatPlatform
from analyzer.api import create_api
from analyzer.platform import SCAPY_IMPORT_ERROR
from analyzer.sensor import run_remote_sensor

try:
    import uvicorn
except Exception:
    uvicorn = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ravynel NDR Platform")
    parser.add_argument(
        "mode",
        nargs="?",
        default="run",
        choices=["run", "replay", "dashboard", "report", "api", "benchmark", "sensor"],
        help="run capture, replay a PCAP, start the app, generate reports, serve the API, benchmark ingest, or run a remote sensor",
    )
    parser.add_argument("--profile", help="Configuration profile name or path to a JSON profile file")
    parser.add_argument("--iface", action="append", dest="interfaces", help="Capture interface to monitor. Repeat to monitor multiple interfaces.")
    parser.add_argument("--pcap", help="Replay a PCAP file")
    parser.add_argument("--playback-speed", type=float, default=None, help="PCAP replay speed multiplier. 0 replays as fast as possible.")
    parser.add_argument("--bpf-filter", default=None, help="BPF filter applied during live capture")
    parser.add_argument("--quick-filter", default=None, help="Quick filter: all, http, dns, external")
    parser.add_argument("--geoip-db", default=None, help="Path to a MaxMind GeoIP database")
    parser.add_argument("--database", default=None, help="SQLite database path or PostgreSQL DSN")
    parser.add_argument("--storage-backend", default=None, help="Storage backend: auto, native, sqlalchemy")
    parser.add_argument("--packet-parser", default=None, help="Packet parser: scapy, dpkt, pyshark, auto")
    parser.add_argument("--ioc-source", action="append", default=None, help="Threat intel source file or URL. Repeat for multiple feeds.")
    parser.add_argument("--webhook-url", default=None, help="Slack or Discord-style webhook URL")
    parser.add_argument("--enable-webhook", action="store_true", help="Enable webhook alert delivery")
    parser.add_argument("--api", action="store_true", help="Start the API server alongside capture or replay")
    parser.add_argument("--api-host", default=None, help="API bind host")
    parser.add_argument("--api-port", type=int, default=None, help="API bind port")
    parser.add_argument("--report-dir", default=None, help="Directory to store generated reports")
    parser.add_argument("--benchmark-packets", type=int, default=None, help="Synthetic packet-context count for dry-run ingest benchmarking")
    parser.add_argument("--collector-url", default=None, help="Remote collector raw-ingest endpoint for sensor mode")
    parser.add_argument("--sensor-id", default=None, help="Stable sensor identifier for remote sensor mode")
    parser.add_argument("--enable-lstm", action="store_true", help="Enable optional TensorFlow/Keras LSTM sequence anomaly model")
    parser.add_argument("--export-iocs", default=None, help="Export observed IOCs to the given file")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the dashboard in a browser")
    parser.add_argument("--historical", action="store_true", help="Serve the dashboard from stored data without starting capture")
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> PlatformConfig:
    config = PlatformConfig.from_profile(args.profile).load_user_settings()
    overrides = {
        "interfaces": args.interfaces if args.interfaces else config.interfaces,
        "pcap_path": args.pcap if args.pcap is not None else config.pcap_path,
        "playback_speed": args.playback_speed if args.playback_speed is not None else config.playback_speed,
        "export_iocs": args.export_iocs if args.export_iocs is not None else config.export_iocs,
        "auto_open_browser": (not args.no_browser) if args.mode == "dashboard" else config.auto_open_browser,
        "dashboard_historical_only": args.historical or config.dashboard_historical_only,
        "bpf_filter": args.bpf_filter if args.bpf_filter is not None else config.bpf_filter,
        "quick_filter": args.quick_filter if args.quick_filter is not None else config.quick_filter,
        "geoip_db": args.geoip_db if args.geoip_db is not None else config.geoip_db,
        "database_path": args.database if args.database is not None else config.database_path,
        "storage_backend": args.storage_backend if args.storage_backend is not None else config.storage_backend,
        "packet_parser": args.packet_parser if args.packet_parser is not None else config.packet_parser,
        "ioc_sources": args.ioc_source if args.ioc_source is not None else config.ioc_sources,
        "webhook_url": args.webhook_url if args.webhook_url is not None else config.webhook_url,
        "webhook_enabled": args.enable_webhook or config.webhook_enabled,
        "api_enabled": args.api or config.api_enabled or args.mode == "dashboard",
        "api_host": args.api_host if args.api_host is not None else config.api_host,
        "api_port": args.api_port if args.api_port is not None else config.api_port,
        "report_dir": args.report_dir if args.report_dir is not None else config.report_dir,
        "benchmark_default_packets": args.benchmark_packets if args.benchmark_packets is not None else config.benchmark_default_packets,
        "lstm_enabled": args.enable_lstm or config.lstm_enabled,
    }
    return config.merge(overrides)


def find_available_port(host: str, preferred_port: int, attempts: int = 20) -> int:
    for offset in range(max(1, attempts)):
        port = preferred_port + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((host, port))
            except OSError:
                continue
            return port
    raise RuntimeError(
        f"Could not find an available port starting at {preferred_port} on {host}. "
        "Use --api-port to choose a different port."
    )


def start_api(platform: ThreatPlatform) -> tuple[threading.Thread, int]:
    if uvicorn is None:
        raise RuntimeError("uvicorn is not installed. Install requirements to enable the API server.")

    actual_port = find_available_port(platform.config.api_host, platform.config.api_port)
    platform.config.api_port = actual_port
    app = create_api(platform.store, platform)
    thread = threading.Thread(
        target=lambda: uvicorn.run(app, host=platform.config.api_host, port=actual_port, log_level="warning"),
        daemon=True,
        name="api-server",
    )
    thread.start()
    return thread, actual_port


def maybe_open_browser(url: str, enabled: bool) -> None:
    if not enabled:
        return

    def opener() -> None:
        time.sleep(1.2)
        try:
            webbrowser.open(url, new=2)
        except Exception:
            return

    threading.Thread(target=opener, name="browser-opener", daemon=True).start()


def run_report_mode(config: PlatformConfig) -> None:
    platform = ThreatPlatform(config)
    paths = platform.generate_reports()
    platform.config.save_reports_on_exit = False
    print("Generated reports:")
    for label, value in paths.items():
        print(f" - {label}: {value}")
    platform.close()


def run_api_mode(config: PlatformConfig) -> None:
    if uvicorn is None:
        raise RuntimeError("uvicorn is not installed. Install requirements to enable the API server.")
    config.api_port = find_available_port(config.api_host, config.api_port)
    platform = ThreatPlatform(config)
    app = create_api(platform.store, platform=None)
    print(f"Serving API on http://{config.api_host}:{config.api_port}")
    try:
        uvicorn.run(app, host=config.api_host, port=config.api_port, log_level="warning")
    finally:
        platform.close()


def run_benchmark_mode(config: PlatformConfig) -> None:
    platform = ThreatPlatform(config)
    try:
        result = platform.benchmark_ingest(config.benchmark_default_packets)
        print("Dry-run ingest benchmark:")
        for key, value in result.items():
            print(f" - {key}: {value}")
    finally:
        platform.close()


def run_sensor_mode(config: PlatformConfig, args: argparse.Namespace) -> None:
    if not args.collector_url:
        raise ValueError("--collector-url is required for sensor mode")
    run_remote_sensor(
        collector_url=args.collector_url,
        interfaces=config.interfaces,
        bpf_filter=config.bpf_filter,
        sensor_id=args.sensor_id or socket.gethostname(),
    )


def run_capture_mode(config: PlatformConfig, mode: str) -> None:
    dashboard_only = mode == "dashboard" and config.dashboard_historical_only and not config.pcap_path
    if SCAPY_IMPORT_ERROR is not None and mode != "dashboard":
        raise RuntimeError(f"Scapy is required for capture and replay modes: {SCAPY_IMPORT_ERROR}")

    platform = ThreatPlatform(config)
    api_thread = None
    app_url = ""
    dashboard_url = ""
    if config.api_enabled:
        requested_port = config.api_port
        api_thread, actual_port = start_api(platform)
        app_url = f"http://{config.api_host}:{actual_port}/app"
        dashboard_url = f"http://{config.api_host}:{actual_port}/dashboard"
        if actual_port != requested_port:
            print(f"Port {requested_port} was busy, so Ravynel moved to a free port.")
        print(f"Live app: {app_url}")
        print(f"Live dashboard: {dashboard_url}")
        if mode == "dashboard":
            maybe_open_browser(app_url, config.auto_open_browser)

    print(platform.geoip.status)
    print(f"Loaded {len(platform.intel.ip_feeds) + len(platform.intel.domain_feeds)} threat intel indicators.")
    print("Passive mode only: no packet injection or blocking is performed automatically.")

    try:
        if mode == "replay":
            if not config.pcap_path:
                raise ValueError("--pcap is required for replay mode")
            print(f"Replaying {config.pcap_path}")
            platform.replay_pcap(config.pcap_path, config.playback_speed)
        elif mode == "dashboard":
            if dashboard_only:
                print("Launcher opened in stored-data mode. Use the app to review stored telemetry and reports.")
            else:
                print(f"Starting live packet capture on interfaces: {config.interfaces or ['default']}")
                if config.bpf_filter:
                    print(f"BPF filter: {config.bpf_filter}")
                try:
                    platform.start_live_capture()
                    print("Live packet capture is running. Open the dashboard for packets, sessions, detections, assets, and reports.")
                except Exception as exc:
                    print(f"Live capture could not start automatically: {exc}")
                    print("The app is still open. Fix capture permissions/dependencies, then use Start Live Capture from the app.")
            while True:
                time.sleep(1)
        else:
            print(f"Starting live capture on interfaces: {config.interfaces or ['default']}")
            if config.bpf_filter:
                print(f"BPF filter: {config.bpf_filter}")
            platform.start_live_capture()
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping platform...")
    finally:
        try:
            platform.stop_capture(drain_timeout=0.75)
        except KeyboardInterrupt:
            print("Forced shutdown requested. Skipping capture drain and closing cleanly.")
        if config.export_iocs:
            path = platform.export_iocs(config.export_iocs)
            print(f"Exported IOCs to {path}")
        should_generate_reports = (
            platform.generated_report_count == 0
            and (platform.packet_count > 0 or platform.alert_count > 0)
        )
        if should_generate_reports:
            report_paths = platform.generate_reports()
            platform.config.save_reports_on_exit = False
            print("Generated reports:")
            for label, value in report_paths.items():
                print(f" - {label}: {value}")
        else:
            print("No new report generated on exit.")
        print("Summary:")
        for key, value in platform.summary().items():
            print(f" - {key}: {value}")
        platform.close()
        if api_thread and api_thread.is_alive():
            print("API server thread will stop when the process exits.")


def main() -> None:
    args = parse_args()
    config = build_config(args)
    if args.mode == "report":
        run_report_mode(config)
        return
    if args.mode == "api":
        run_api_mode(config)
        return
    if args.mode == "benchmark":
        run_benchmark_mode(config)
        return
    if args.mode == "sensor":
        run_sensor_mode(config, args)
        return
    run_capture_mode(config, args.mode)


if __name__ == "__main__":
    main()
