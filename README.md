# Dynamic Firewall Enforcement Engine

## Overview
This module is part of an Advanced Threat Intelligence Platform for the Finance & Banking sector.

The system monitors MongoDB for high-risk threat indicators and dynamically enforces firewall rules using iptables.

## Features
- Real-time MongoDB monitoring
- Risk-based IP blocking
- Secure IP validation
- Persistent blocked IP storage
- Logging and audit trail
- Daemon-style continuous execution

## Technologies Used
- Python
- MongoDB
- Linux iptables
- systemd

## How to Run
sudo python3 firewall_engine.py
