from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

PACKET_COUNT = 20


def analyze_packet(packet):

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    print("\n" + "=" * 60)
    print("Time        :", datetime.now().strftime("%H:%M:%S"))
    print("Source IP   :", ip.src)
    print("Destination :", ip.dst)

    if packet.haslayer(TCP):
        print("Protocol    : TCP")
        print("Source Port :", packet[TCP].sport)
        print("Dest Port   :", packet[TCP].dport)

    elif packet.haslayer(UDP):
        print("Protocol    : UDP")
        print("Source Port :", packet[UDP].sport)
        print("Dest Port   :", packet[UDP].dport)

    elif packet.haslayer(ICMP):
        print("Protocol    : ICMP")

    else:
        print("Protocol    : IP")

    print("Packet Size :", len(packet), "bytes")


print("=" * 60)
print("          BASIC NETWORK SNIFFER")
print("=" * 60)
print("Starting packet capture...")
print("Capturing 20 packets...")
print("Please use your internet while it is running.\n")


sniff(
    filter="ip",
    prn=analyze_packet,
    count=PACKET_COUNT,
    store=False
)

print("\nCapture completed!")