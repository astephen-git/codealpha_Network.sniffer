from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("="*80)
    
    # Basic Packet Info
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"[+] Source IP: {src_ip}")
        print(f"[+] Destination IP: {dst_ip}")
        print(f"[+] Protocol: {protocol} ({ip_layer.name})")
        
        # Check Protocol Type
        if TCP in packet:
            print("[*] TCP Packet")
            print(f"    Source Port: {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("[*] UDP Packet")
            print(f"    Source Port: {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("[*] ICMP Packet")

        # Payload Info
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("[*] Payload:")
            print(payload)

    else:
        print("[!] Non-IP Packet")

# Start Sniffing
print("[*] Starting Packet Sniffer...\nPress Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=0)
