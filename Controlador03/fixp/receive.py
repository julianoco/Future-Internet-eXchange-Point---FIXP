#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

#from etarch_header import ETARCH

def handle_pkt(pkt):    

    if Ether in pkt: #and str(pkt[IP].dst) == '192.168.184.102':  #and str(pkt[Ether].dst) == '00:00:00:00:00:02':

        if(pkt[Ether].type == 0x800):
            print "got a packet IP"
            print "SRC IP  : %s" % pkt[IP].src
            print "DST IP  : %s" % pkt[IP].dst
            print "SRC MAC : %s" % pkt[Ether].src
            print "SRC MAC : %s" % pkt[Ether].dst
        elif(pkt[Ether].type == 0x880):
            print "got a packet Etarch"
            #print "SRC IP  : %s" % pkt[IP].src
            #print "DST IP  : %s" % pkt[IP].dst
            print "SRC MAC : %s" % pkt[Ether].src
            print "SRC MAC : %s" % pkt[Ether].dst

        pkt.show2()
        sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    ifaces.sort()
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = 'eth0',
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
