# PCAP Analysis Report Card

## Overview
A Flask web application that analyzes uploaded PCAP files using the Scapy library and generates a security report card.

## Current State
- **Status**: Complete and functional
- **Last Updated**: December 6, 2025

## Features
1. **File Upload**: Simple web interface to upload PCAP/PCAPNG files
2. **Protocol Analysis**: Counts packets and identifies top 3 protocols (TCP, UDP, ICMP, ARP, DNS)
3. **Security Check**: Scans packet payloads for cleartext passwords
4. **Report Card**: Clean HTML output showing analysis results with warnings

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

### Routes
- `GET /` - Upload form for PCAP files
- `POST /analyze` - Processes uploaded file and returns report card

### Analysis Functions
1. `get_protocol_summary(packets)` - Returns top 3 protocols with counts and percentages
2. `security_check_passwords(packets)` - Counts packets containing "password" in payload

## User Preferences
- Single-file implementation preferred for simplicity
- Basic HTML/CSS styling (no external frameworks)
