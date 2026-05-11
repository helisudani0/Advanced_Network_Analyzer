# LAN Coverage Guide

Ravynel is a passive network detection product. It can only analyze traffic it can see.

## What Local Adapter Capture Sees

On a normal laptop or workstation, local capture sees:

- traffic to and from that host
- broadcast and multicast traffic visible to the adapter
- some local discovery protocols

It will not automatically see every device-to-device conversation on a switched LAN.

## How Enterprises Monitor the Whole Network

Use one of these authorized defensive deployment patterns:

- Gateway capture: install Ravynel on the router, firewall, or gateway where traffic naturally crosses.
- SPAN or mirror port: mirror switch traffic to a monitoring NIC connected to Ravynel.
- Network TAP: use a physical tap for reliable packet visibility.
- Distributed sensors: run Ravynel sensors on key hosts or network segments and forward telemetry to the collector.
- PCAP replay: analyze captures exported from firewalls, IDS sensors, Wireshark, Zeek, or packet brokers.

## Product Guidance

The console includes a `Monitor All Local Adapters` workflow. That means all adapters on the machine running Ravynel, not every device on the LAN. For full company-wide visibility, deploy SPAN/TAP/gateway capture or remote sensors.

