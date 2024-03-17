from scapy.all import sniff, IP, ICMP
import pyfiglet
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Detected packet from {src_ip} to {dst_ip}")

        if ICMP in packet:
            print("ALERT: Suspicious ICMP packet detected!")

def monitor_traffic(interface="eth0"):
    print(f"[*] Starting network traffic monitoring on interface {interface}\n ")
    sniff(iface=interface, prn=analyze_packet, store=False)
def main():
        banner = pyfiglet.figlet_format("Snoopy")
        print(banner)
        print("           By Usama Ishtiaq \n      ")

if __name__ == "__main__":
    main()
    monitor_traffic()

