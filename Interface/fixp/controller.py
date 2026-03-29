#!/usr/bin/env python
import sys
import struct
import os
import socket

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

#from xpto_header import XPTO
from etarch_header import ETARCH


def client(etherType, dstAddr, dstMAC, outPort):
    try:
        address = '192.168.231.101'
        port = 9999

        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        result = clientSocket.connect((address, port))

        if etherType == 0x800:
            command = "table_add FIXP_Switch_Ingress.ipv4_forward %s/32 => FIXP_Switch_Ingress.ipv4_SetSpec %s %d" % (dstAddr, dstMAC, outPort)

        clientSocket.sendall(command)

    except socket.error as err:
        print "socket error\n"

    except:
        print "exception\n"

    clientSocket.close()


def handle_pkt(pkt):

    srcAddr = ""
    dstAddr = ""
    srcMAC = ""
    dstMAC = ""
    outPort = 0

    if Ether in pkt:
        if pkt[Ether].type == 0x800:
            if IP in pkt:
                if ((str(pkt[IP].dst) == '192.168.184.102') or (str(pkt[IP].dst) == '192.168.171.104')):
                    srcAddr = pkt[IP].src
                    srcMAC = pkt[Ether].src
                    dstAddr = pkt[IP].dst
                    dstMAC = pkt[Ether].dst

                    if str(pkt[IP].dst) == '192.168.184.102':
                        outPort = 3
                    else :
                        outPort = 2

                    print "srcAddr : %s" % srcAddr
                    print "srcMAC  : %s" % srcMAC
                    print "dstAddr : %s" % dstAddr
                    print "dstMAC  : %s" % dstMAC
                    print "outPort : %d" % outPort

                    client(pkt[Ether].type, dstAddr, dstMAC, outPort)


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()

    sniff(iface = iface, prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
