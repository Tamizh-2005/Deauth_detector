# Deauth Culprit Detection & Localization Tool

## 📌 Description

A Python-based tool to detect Wi-Fi deauthentication attacks in crowded areas (e.g., classrooms, CTFs) and estimate attacker proximity using RSSI.

## 🔧 Requirements

- Python 3.6+
- Linux with Wi-Fi adapter in monitor mode
- Dependencies:
  - `scapy`
  - `rich`

## 📥 Setup

```bash
pip install -r requirements.txt
sudo airmon-ng start wlan0  # Replace wlan0 with your interface
```

## 🚀 Usage

```bash
sudo python3 deauth_detector.py -i wlan0mon
```

## 💾 Output

Logs are saved automatically to `sample_logs/deauth_logs.csv` when you stop the program using `Ctrl+C`.

## ⚠️ Alerts

The system triggers an alert when:
- A device sends repeated deauth frames
- RSSI exceeds proximity threshold (-50 dBm)

## 📁 Sample Logs

```
MAC,Timestamp,RSSI
44:55:66:77:88:99,2025-05-21 10:10:34,-45
44:55:66:77:88:99,2025-05-21 10:11:00,-48
```

## 🔒 Advanced Notes

- Designed to flag spoofed MACs by signal similarity
- Can be extended for triangulation or heatmap visualization

---
Professional tool for network security students, cybersecurity CTFs, or audit professionals.