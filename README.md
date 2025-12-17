# Advanced Explainable Network Threat Analyzer

## Overview

This project is a Python-based, SOC-style network traffic analyzer designed to monitor live network activity and identify potentially malicious behavior in an explainable and context-aware manner. Unlike basic packet sniffers, the analyzer focuses on reducing false positives while providing clear, human-readable explanations for detected threats.

The tool passively inspects network traffic and classifies DNS, mDNS, HTTP/HTTPS, and general packet behavior, applying intelligent risk scoring and suppression logic similar to commercial intrusion detection systems.

## Key Features

* Live packet capture using Scapy
* DNS and mDNS query identification and classification
* HTTP and HTTPS traffic awareness
* Context-aware traffic burst and flood detection
* Private IP and cloud service traffic suppression
* Risk scoring with automatic score decay over time
* Explainable threat labeling for analyst-friendly output
* Low false-positive design
* Passive analysis only (no packet injection or attacks)

## Technology Stack

* Language: Python
* Library: Scapy
* Environment: Windows / Linux (Administrator or sudo required)

## How It Works

1. Captures live network packets from the active network interface.
2. Maintains time-based traffic windows per source IP.
3. Classifies traffic types such as DNS, mDNS, and HTTP/HTTPS.
4. Detects anomalous behavior based on packet frequency and patterns.
5. Applies contextual rules to ignore:
   * Internal/private IP addresses
   * Outbound client traffic to cloud and CDN services
6. Assigns and updates threat scores only when behavior exceeds realistic thresholds.
7. Generates analyst-readable alerts with clear explanations.

## Example Output

The analyzer provides structured console output, including:

* DNS queries and destination domains
* Local service discovery traffic (mDNS)
* HTTP/HTTPS request destinations
* Risk level, threat description, reasoning, and score when anomalies are detected

This makes the output understandable even for non-specialists reviewing network activity.

## Installation

Install the required dependency: pip install scapy

## How to run

Run the script with administrative privileges: python app.py

(On Windows, run Command Prompt as Administrator.
On Linux, use sudo.)

## Limitations

* Passive monitoring only (no active defense or blocking)
* Not intended to replace full IDS/IPS solutions
* Designed for learning purposes

## Ethical Notice

This tool performs passive traffic analysis only. It does not generate malicious traffic, exploit systems, or perform unauthorized actions. It is intended strictly for learning and defensive security research.

## Author- Heli Sudani

Developed as part of an advanced hands-on cybersecurity and IT learning project.

