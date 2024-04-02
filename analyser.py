import scapy.all as scapy
import socket
import os
import time
from datetime import datetime
import subprocess

# manual text colored
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# for date time
now = datetime.now()

# banner
print(os.system("clear"))
time.sleep(2)
print(os.system('cat banner/banner.txt'))
# print(bcolors.BOLD+bcolors.OKBLUE+f" Traffic Analysing.. "+bcolors.ENDC)
subprocess.Popen(['xterm'])

# Dictionary mapping protocol numbers to their names
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add more protocols as needed
}

def get_protocol_name(proto_num):
    return protocol_names.get(proto_num, "Unknown")

def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except socket.herror:
        return "Unknown IP"


def sniff_packet(packet):
    if packet.haslayer(scapy.IP):
        # source ip management
        ip_src = packet[scapy.IP].src
        src_hostname = get_hostname(ip_src)
        # destination ip management
        ip_dst = packet[scapy.IP].dst
        # dst_hostname = packet[scapy.IP].dst
        dst_hostname = get_hostname(ip_dst)
        # protocol management
        protocol = packet[scapy.IP].proto
        protocol_name = get_protocol_name(protocol)

        # if ip_src == "0.0.0.0" or ip_src == "127.0.0.1" or ip_src.startswith("169.254."):  # Check for common unknown source IP addresses
        if ip_src == "0.0.0.0" or ip_src == "127.0.0.1" or ip_src.startswith("34."):  # Check for common unknown source IP addresses
            output = bcolors.BOLD+bcolors.FAIL+f" Unknown source IP detected: {ip_src} - Hostname: {get_hostname(ip_src)}"+bcolors.ENDC
            os.system(f"echo {output} >> scan-output/Unknown-IP-List.txt")
            print(output)
            
            # # perform_nmap_scan(ip_src)
            # # saved_files = f'scan-output/{src_hostname}_scanned_{now.strftime("%Y-%m-%d_%H-%M-%S")}'
            # timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            # nmap_output_file = f"scan-output/nmap_scan_{ip_src}_{timestamp}.txt"
            # nmap_command = subprocess.Popen(['xterm', '-e', f'nmap -Pn -T4 -sV -sC -vv {ip_src} -oN {nmap_output_file}'])
            # # nmap_command = f'nmap -Pn -sV {ip_src} > {nmap_output_file}'
            # # process = subprocess.run(nmap_command, shell=True)
            # # process.wait()
        else:
            # printing output
            # print(os.system("clear"))
            print(bcolors.BOLD+bcolors.OKGREEN+f" Source: {ip_src} - {src_hostname}, Destination: {ip_dst} - {dst_hostname}, Protocol: {protocol_name}"+bcolors.ENDC)
            

# import nmap

# def perform_nmap_scan(ip_address):
#     scanner = nmap.PortScanner()
#     scanner.scan(ip_address, arguments='-Pn -sV')  # Adjust scan options as needed
#     print(f"Nmap scan report for {ip_address}:")
#     for host in scanner.all_hosts():
#         print(f"Host: {host}")
#         for proto in scanner[host].all_protocols():
#             print(f"Protocol: {proto}")
#             ports = scanner[host][proto].keys()
#             for port in ports:
#                 state = scanner[host][proto][port]['state']
#                 service = scanner[host][proto][port]['name']
#                 print(f"Port: {port} ({state}) - Service: {service}")


def start_sniffing(interface):
    scapy.sniff(iface=interface, prn=sniff_packet, store=False)

if __name__ == "__main__":
    interface = "wlan0"  # Change this to your network interface
    start_sniffing(interface)

