
from scapy.all import ARP, Ether, srp
import ipaddress
from colorama import init, Fore, Style

# initialize coloroma
init(autoreset=True)


def print_banner():
    # Print the banner with colors
    banner = f"""{Fore.CYAN}
    ================================
          C9b3rD3vi1  Network Scanner
    ================================
    """
    print(banner)


def scan_network(network):
    # Create an ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse the results
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def main():
    # Define the network to scan (e.g., '192.168.1.0/24')
    network = input(f"{Fore.YELLOW}Enter the network to scan (e.g., '192.168.1.0/24'): ")
    
    try:
        # Validate network input
        ipaddress.ip_network(network)
        
        print(f"{Fore.GREEN}Scanning the network: {network}...")
        devices = scan_network(network)

        print("\nConnected devices:")
        print("IP Address\t\tMAC Address")
        print("-----------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    
    except ValueError:
        print(f"{Fore.RED}Invalid network format. Please use CIDR notation (e.g., '192.168.1.0/24').")

if __name__ == "__main__":
    main()
