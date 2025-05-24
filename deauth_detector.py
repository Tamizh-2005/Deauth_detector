from scapy.all import *
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
log_data = {}
DEAUTH_CODES = [0x0C, 0x0A]  # deauth + disassoc

def is_deauth(packet):
    return packet.haslayer(Dot11Deauth) or (packet.haslayer(Dot11) and packet.type == 0 and packet.subtype in DEAUTH_CODES)

def log_deauth(pkt):
    mac = pkt.addr2
    rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if mac not in log_data:
        log_data[mac] = []

    log_data[mac].append((timestamp, rssi))

    if len(log_data[mac]) > 10:
        log_data[mac] = log_data[mac][-10:]  # keep last 10

    if rssi > -50:
        console.print(f"[bold red]ALERT: High RSSI from {mac} -> {rssi} dBm @ {timestamp}[/]")

def packet_handler(pkt):
    if is_deauth(pkt):
        log_deauth(pkt)

def sniff_packets(interface):
    console.print(f"[green]Sniffing on {interface}... Press Ctrl+C to stop.[/]")
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Wi-Fi Deauth Detector")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface")
    args = parser.parse_args()

    try:
        sniff_packets(args.interface)
    except KeyboardInterrupt:
        console.print("[yellow]Stopped sniffing. Saving logs...[/]")
        with open("sample_logs/deauth_logs.csv", "w") as f:
            f.write("MAC,Timestamp,RSSI\n")
            for mac, entries in log_data.items():
                for timestamp, rssi in entries:
                    f.write(f"{mac},{timestamp},{rssi}\n")
        console.print("[green]Logs saved to sample_logs/deauth_logs.csv[/]")