# 🕵️‍♂️ Basic Network Sniffer - Python & Scapy

A powerful yet simple Python-based network sniffer to capture and analyze packets in real-time using the Scapy library. Perfect for beginners learning about network protocols, packet structures, and traffic flow in a local network.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🚀 Features

- 🔍 Live packet sniffing from network interfaces
- 📦 Extracts source & destination IPs
- 🌐 Identifies transport layer protocols (TCP, UDP, ICMP)
- 🧠 Displays raw packet payload (if present)
- ⚡ Built using powerful **Scapy** library
- 💡 Educational project to learn network protocols & structures

---

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/network-sniffer.git
cd network-sniffer
```
### Install Requirements
```bash
pip install scapy
```
⚠️ Note: This script must be run with root privileges for packet capturing.

### To Use
```bash
sudo python3 sniffer.py
```
Press `CTRL+C` to stop sniffing.
