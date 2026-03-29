#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
import datetime

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

from etarch_header import ETARCH
from novagenesis_header import NOVAGENESIS

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv) != 4:
        print 'pass 3 arguments:./send.py <destination addr> <EtherType> <network interface>'
        exit(1)

    if int(sys.argv[2][2:],16) == 0x0800:
    	addr = socket.gethostbyname(sys.argv[1])
    elif int(sys.argv[2][2:],16) == 0x0880:
        addr = sys.argv[1]
    elif int(sys.argv[2][2:],16) == 0x1234:
        addr = sys.argv[1]

#    iface = get_if()
    iface = sys.argv[3]

    #data = open('resultados.txt','a')

    MAX_TESTS = 2

    for j in range(1,MAX_TESTS):

        now = datetime.datetime.now()

        #while now.second%30 != 0:
        #    now = datetime.datetime.now()

        #print "envios iniciados N:%d" % (j)

        MAX_PACKETS = 2

        start_tests = datetime.datetime.now()

        #IPV4
        if int(sys.argv[2][2:],16) == 0x0800:
            for i in range(1, MAX_PACKETS):
                #print "sending IPV4 on interface %s to %s" % (iface, str(addr))
                pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
                pkt = pkt / IP(dst=addr)
                pkt = pkt / TCP(dport=1234, sport=random.randint(49152,65535))
                pkt = pkt /  ('ipv4 message %d' % (i))
                #pkt.show2()
                sendp(pkt, iface=iface, verbose=False)
                #time.sleep(.1)

        #ETARCH
        elif int(sys.argv[2][2:],16) == 0x0880:
            for i in range(1, MAX_PACKETS):
                #print "sending ETARCH on interface %s to %s" % (iface, addr)
                pkt = Ether(src='%s' % (addr), dst='00:00:00:00:00:00')
                pkt = pkt / ETARCH(cpl=2,cpt=0,cpid=1,pl=1,p='X' )
                pkt = pkt / ('etarch message %d' % (i))
                #pkt.show2()
                sendp(pkt, iface=iface, verbose=False)
                #time.sleep(.1)

        #NOVA GENESIS
        elif int(sys.argv[2][2:],16) == 0x1234:
            for i in range(1, MAX_PACKETS):
                #print "sending NOVA GENESIS on interface %s to %s" % (iface, addr)
                pkt = Ether(src=get_if_hwaddr(iface), dst='%s' % (addr))
                pkt = pkt / NOVAGENESIS(msgId=0, fragSeq=0, msgSize=0 )
                pkt = pkt / ('nova genesis message %d' % (i))
                #pkt.show2()
                sendp(pkt, iface=iface, verbose=False)
                #time.sleep(.1)


        end_tests = datetime.datetime.now()

        #print "envios terminados N:%d" % (j)

        delta = end_tests - start_tests
        print "duracao: %d(ms)" % (int(delta.total_seconds() * 1000))

        #if int(sys.argv[2][2:],16) == 0x0800:
        #    data.write("IP %d %d(ms)\n" % (MAX_TESTS-1, int(delta.total_seconds() * 1000)))

        #elif int(sys.argv[2][2:],16) == 0x0880:
        #    data.write("ET %d %d(ms)\n" % (MAX_TESTS-1, int(delta.total_seconds() * 1000)))

        #elif int(sys.argv[2][2:],16) == 0x1234:
        #    data.write("NG %d %d(ms)\n" % (MAX_TESTS-1, int(delta.total_seconds() * 1000)))

    #data.close()

if __name__ == '__main__':
    main()
