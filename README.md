
# Packet Sniffer Using Scapy

## Description
This is a Python-based packet sniffer built with the `scapy` library. It captures network packets and provides detailed analysis, including source and destination IP addresses, protocols, and payload data.

## Features
- Captures and analyzes IPv4, TCP, and UDP packets.
- Displays detailed information such as source and destination IP addresses, ports, and protocols.
- Outputs raw payload data in hexadecimal format.

## Requirements
- Python 3.x
- `scapy` library

## Installation
1. Clone this repository or download the script file.
2. Install the required library using pip:
   ```bash
   pip install scapy
   ```

## Usage
1. Run the script with administrative privileges:
   ```bash
   sudo python Pack-Sniff.py
   ```
   or
   ```bash
   sudo python3 Pack-Sniff.py
   ```
3. The script will capture packets from the specified network interface or automatically detect an interface if none is provided.

4. Stop the script by pressing `Ctrl+C`.

## Ethical Considerations
- This tool is intended for educational and authorized purposes only.
- Use it responsibly and only on networks where you have explicit permission to monitor traffic.
- Unauthorized use of packet sniffers may violate laws and regulations.

## Disclaimer
The author is not responsible for any misuse of this tool. Use it at your own risk and ensure compliance with applicable laws.

## Support
For issues or questions, please contact iptcp.198@gmail.com.
