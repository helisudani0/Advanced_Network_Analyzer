from __future__ import annotations

import base64
import json
import time
from typing import Iterable, Optional
from urllib.request import Request, urlopen


try:
    from scapy.all import sniff
except Exception as exc:
    sniff = None
    SCAPY_SENSOR_IMPORT_ERROR = exc


def _post_raw_packet(collector_url: str, payload: dict) -> None:
    request = Request(
        collector_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10):
        return


def run_remote_sensor(
    collector_url: str,
    interfaces: Iterable[str],
    bpf_filter: str = "",
    sensor_id: str = "",
) -> None:
    """Run a passive raw-packet forwarder for distributed collection.

    The collector should point at the platform endpoint:
    http://host:port/remote/ingest/raw
    """
    if sniff is None:
        raise RuntimeError(f"Scapy is required for remote sensor mode: {SCAPY_SENSOR_IMPORT_ERROR}")

    iface_list = list(interfaces) or [None]
    print(f"Remote raw-packet sensor online. Collector: {collector_url}")
    print(f"Interfaces: {iface_list}")
    if bpf_filter:
        print(f"BPF filter: {bpf_filter}")

    def forward(packet, iface: Optional[str] = None) -> None:
        try:
            payload = {
                "sensor_id": sensor_id,
                "interface": iface or "",
                "timestamp": float(getattr(packet, "time", time.time())),
                "linktype": "ethernet",
                "packet_base64": base64.b64encode(bytes(packet)).decode("ascii"),
            }
            _post_raw_packet(collector_url, payload)
        except Exception:
            return

    while True:
        for iface in iface_list:
            sniff(
                iface=iface,
                store=False,
                filter=bpf_filter or None,
                prn=lambda packet, current_iface=iface: forward(packet, current_iface),
                timeout=1,
            )
