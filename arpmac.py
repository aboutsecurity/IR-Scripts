#!/usr/bin/env python

# A simple python script to find MAC addresses in the local network using ARP
# requests/replies.
#
# Version 2 - Included option to enable Nmap Fingerprinting
# resolution using Nmap module for Scapy.
#
# Note that this script requires tcpdump and scapy to be installed.
# Additionally, it requires root privileges to run in order to craft and send
# packets over the wire.
#
# Don't forget to edit nmap.py (installed with Scapy module) to indicate the location of your nmap
# fingerprinting file. If you don't have one, download it from here: http://nmap.org/dist-old/nmap-4.22SOC8.tgz

##############################
#                            #
# Ismael Valenzuela (c) 2011 #
#                            #
##############################


scapy_builtins = __import__('scapy.all', globals(),  locals(),'.').__dict__
__builtins__.__dict__.update(scapy_builtins)

import sys
from scapy.all import srp,Ether,ARP,conf
from scapy.modules.nmap import *

def scan(net,nmap):
  """
  This function uses Scapy to craft and send ARP requests over the wire storing
  answered and answered packets for offline analysis
  """
  conf.verb=0
  ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),
              timeout=2) # add inter=0.1 if missing packets

  print r"MAC, IP"
  for snd,rcv in ans:
    print rcv.sprintf(r"%Ether.src%, %ARP.psrc%")
    if nmap:
      address=rcv.sprintf(r"%ARP.psrc%")
      print nmap_fp(address)[1], '\n'


def main():

  if len(sys.argv) != 3:
    print "\nUsage: arpmac {--fingerprint | --no-fingerprint} <network>\n\n eg: arpmac --fingerprint 192.168.1.0/24\n eg: arpmac --no-fingerprint 192.168.1.0/24\n\n"
    sys.exit(1)

  option = sys.argv[1]
  network = sys.argv[2]
  if option == '--fingerprint':
    scan(network,1)
  elif option == '--no-fingerprint':
    scan(network,0)
  else:
    print 'Unknown option: ' + option
    sys.exit(1)

if __name__=='__main__':
  main()
