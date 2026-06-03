from scapy.all import *

packets = sniff(count=10)

for pkt in packets:
    pkt.show()

print(conf.use_pcap)

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n" + "=" * 50)
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol       : ICMP")

        else:
            print(f"Protocol Number: {protocol}")

        print(f"Packet Length  : {len(packet)} bytes")

        payload = bytes(packet.payload)

        if payload:
            print("\nPayload Preview:")
            print(payload[:64])

def main():
    print("Network Packet Analyzer")
    print("Capturing packets... Press Ctrl+C to stop.\n")

    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()