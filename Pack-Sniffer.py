from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    """Callback function to process each captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nPacket Captured:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto}")
        
        # Check for TCP and UDP layers
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"  TCP Segment:")
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"  UDP Segment:")
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")
        
        # Display raw payload if available
        if packet.payload:
            print(f"  Payload:")
            print(packet.payload.original.hex())

def start_sniffer(interface=None):
    """Starts packet sniffing."""
    print("Starting packet sniffer. Press Ctrl+C to stop.")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    # Change 'eth0' to your desired network interface or leave None for automatic selection
    start_sniffer(interface=None)
