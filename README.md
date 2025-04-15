# TLS 1.2 PSK Key Derivation Tool
 
A Python script using Scapy to parse pcap files, identify TLS 1.2 Pre-Shared Key (PSK) handshakes, and derive the corresponding session keys based on user-provided PSKs.
 
This tool is designed for network analysis and educational purposes to understand the TLS 1.2 PSK key derivation process.
 
## Features
 
* Parses pcap or pcapng network capture files.
* Identifies TLS 1.2 ClientHello and ServerHello messages within TCP streams.
* Extracts Client Random, Server Random, and the negotiated Cipher Suite ID.
* Supports processing multiple pcap files and testing multiple PSKs against each file in batch mode.
* Calculates the Pre-Master Secret (PMS) for pure PSK modes based on the provided PSK.
* Derives the Master Secret (MS) using the TLS 1.2 PRF.
* Expands the MS into the required key block.
* Extracts Session Keys (Encryption Keys, MAC Keys, Initialization Vectors/Nonces) based on the parameters of supported pure PSK cipher suites (e.g., `TLS_PSK_WITH_AES_128_CBC_SHA256`, `TLS_PSK_WITH_AES_128_GCM_SHA256`).
* Prints all derived cryptographic material (PMS, MS, Key Block, Session Keys) in hexadecimal format upon successful derivation.
* Provides a summary of successful file/PSK combinations at the end of batch processing.
 
## ⚠️ Security Warning & Disclaimer
 
* This script is intended for **educational and network analysis purposes ONLY**.
* **CRITICAL: NEVER commit your actual Pre-Shared Keys (PSKs)** or sensitive/revealing file paths directly into the script, especially if uploading to public repositories like GitHub. Use placeholders in the committed code.
* Handle PSKs securely. For actual use, consider loading them from environment variables, command-line arguments, or secure configuration files **not** tracked by Git (use a `.gitignore` file).
* Use this tool responsibly and **only on network traffic you are explicitly authorized to capture and analyze.** Unauthorized network interception and decryption is illegal and unethical.
 
## Requirements
 
* Python 3.x
* Scapy library
 
## Installation
 
Install the Scapy library using pip:
 
```bash
pip install scapy
# or use pip3 if needed
# pip3 install scapy
