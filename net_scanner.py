
from scapy.all import ARP, Ether, srp
import ipaddress
from colorama import init, Fore, Style

import pyfiglet


# initialize coloroma
init(autoreset=True)

# Initialize my colorama and ASCII BANNER
#ascii_banner = pyfiglet.figlet_format(f"{Fore.CYAN} C9b3rD3vi1")
#print(ascii_banner)


def print_banner():
    # Print the banner with colors
    # pyfiglet.figlet_format to be used
    banner = f"""{Fore.CYAN}
    ================================
     C9b3rD3vi1  Network Scanner
    ================================
    """

    print(banner)




# Network Scanner tool functions
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



# Main function to start the network scanner tool

def main():

    print('\n')
    # Define the network to scan (e.g., '192.168.1.0/24')
    network = input(f"{Fore.YELLOW}Enter the network to scan (e.g., '192.168.1.0/24'): ")
    
    try:
        # Validate network input
        ipaddress.ip_network(network)
        print('\n')
        print(f"{Fore.GREEN}Scanning the network: {network}...")
        print('\n')
        # Scan the network and get connected devices
        devices = scan_network(network)

        print("\nConnected devices:")
        print("IP Address\t\tMAC Address")
        print("-----------------------------")
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    
    except ValueError:
        print(f"{Fore.RED}Invalid network format. Please use CIDR notation (e.g., '192.168.1.0/24').")

if __name__ == "__main__":

    print_banner()
    main()
