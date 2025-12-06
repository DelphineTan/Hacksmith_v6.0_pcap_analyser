# PCAP Analysis Report Card

## Overview
A Flask web application that analyzes uploaded PCAP files using the Scapy library and generates a comprehensive security report card with intrusion detection capabilities.

## Current State
- **Status**: Complete and functional with advanced intrusion detection
- **Last Updated**: December 6, 2025

## Features

### Core Features
1. **File Upload**: Web interface to upload PCAP/PCAPNG files (up to 500MB)
2. **Protocol Analysis**: Counts packets and identifies top 3 protocols (TCP, UDP, ICMP, ARP, DNS)
3. **Security Check**: Scans packet payloads for cleartext passwords
4. **Report Card**: Clean HTML output showing analysis results with warnings

### Advanced Intrusion Detection
5. **Port Sweep Detection**: Detects when a single source IP sends TCP SYN packets to more than 15 unique ports on the same destination IP - indicates potential port scanning activity
6. **Data Exfiltration Detection**: Identifies asymmetrical data flows where outbound:inbound byte ratio exceeds 50:1, flagging potential data exfiltration
7. **Beginner Narrative**: Human-readable summary explaining traffic patterns, top destinations, and protocol usage

## Project Structure
```
/
├── main.py          # Single-file Flask application with all logic
├── pyproject.toml   # Python dependencies
├── replit.md        # This file
└── .gitignore       # Git ignore rules
```

## How to Run
The application runs on port 5000. Use the Flask Server workflow or:
```bash
python main.py
```

## Technical Details
- **Framework**: Flask 3.x
- **Packet Analysis**: Scapy 2.x
- **Python**: 3.11
- **Max Packets**: 100,000 per analysis (for performance)

### Routes
- `GET /` - Upload form for PCAP files
- `POST /analyze` - Processes uploaded file and returns report card

### Analysis Functions
1. `analyze_pcap_streaming(file_path)` - Main streaming analysis function, collects all data in single pass
2. `detect_enumeration(scan_data)` - Port sweep detection (threshold: >15 unique ports)
3. `detect_exfiltration(flow_data)` - Asymmetrical flow detection (ratio: >50:1, min: 10KB outbound)
4. `generate_narrative(protocol_summary, destination_counts, total_packets)` - Generates beginner-friendly traffic summary

### Detection Thresholds
- Port Sweep: Single source to >15 unique destination ports (TCP SYN only)
- Data Exfiltration: >50:1 outbound/inbound ratio with minimum 10KB outbound

## User Preferences
- Single-file implementation preferred for simplicity
- Basic HTML/CSS styling (no external frameworks)
