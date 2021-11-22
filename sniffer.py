"""
This script uses the scapy sniff() function to capture network packets.

if we want to see a detailed lists of all the scapy methjods available we should run the python repl and then run scapy.lsc() function.
"""

import logging
import subprocess

#This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    print("Get it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()

# In the next section, we must ask the user for some parameter; interface in which to perform the packets sniffing and the number of pakets to sniff.  Also the time alloted to perform the operations.

print('Make sure the application is running with root priviledges!!!')

#Setting network interface in promiscuous mode
#Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface controller (NIC) or wireless network interface controller (WNIC).

#Section: asking the user for the Interface in which to perform the packets sniffing

net_iface = input('[+] Enter the interface on which to run the sniffer (like "eth1"): ')
subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

print(f'Interface {net_iface} was set to PROMISC mode.')

#Section: Asking the user for the number of packets to sniff (the "count" parameter)

pkt_to_sniff = input('Enter the number of packets to capture (0 is infinity): ')

#Considering if the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print(f'The program will capture {pkt_to_sniff} packets.')
    print('\n')
elif int(pkt_to_sniff) == 0:
    print('The program will capture packets until the timeout expires.')
    print('\n')
    

