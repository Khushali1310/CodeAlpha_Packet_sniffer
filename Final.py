from scapy.all import sniff, Ether, IP, TCP, UDP

def process_packet(packet):
    """Processes captured packets."""
    if Ether in packet:
        eth = packet[Ether]
        print("\nEthernet Frame:")
        print(f"Destination MAC: {eth.dst}, Source MAC: {eth.src}, EtherType: {eth.type}")
        
        # IPv4
        if IP in packet:
            ip = packet[IP]
            print("IPv4 Packet:")
            print(f"Source IP: {ip.src}, Destination IP: {ip.dst}, Protocol: {ip.proto}")
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                print("TCP Segment:")
                print(f"Source Port: {tcp.sport}, Destination Port: {tcp.dport}")
                print(f"Flags: {tcp.flags}")
                if tcp.payload:
                    print("Data:")
                    print(tcp.payload)
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                print("UDP Segment:")
                print(f"Source Port: {udp.sport}, Destination Port: {udp.dport}")
                if udp.payload:
                    print("Data:")
                    print(udp.payload)

def main():
    """Main function to start packet sniffing."""
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
