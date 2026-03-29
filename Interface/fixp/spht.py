
#!/usr/bin/env python
import sys
import struct
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

ARQUITETURA_IPV4   = 0x0800
ARQUITETURA_ETARCH = 0x0880
ARQUITETURA_FIXP   = 0x0900
ARQUITETURA_NG     = 0x1234  

#Configuracas das interfaces de transmissao para os controladores
IFACE_0           = 'eth0'
IFACE_1           = 'eth1'
IFACE_2           = 'eth2'
IFACE_3           = 'eth3'

def choiceIface(arquiteturaPrincipalP, arquiteturaEncapsuladaP) :

    #essa funcao sera desnecessaria, pois as primitivas irao apenas para uma interface

    #caso tenha varias interfaces, o ideal e uma interface para varios switches

    if(arquiteturaPrincipalP != ARQUITETURA_FIXP) :

      if arquiteturaPrincipalP == ARQUITETURA_IPV4 :

        return IFACE_1

      elif(arquiteturaPrincipalP == ARQUITETURA_ETARCH) :   

        return IFACE_1

      elif(arquiteturaPrincipalP == ARQUITETURA_NG) :   

        return IFACE_1

    else :

      if arquiteturaEncapsuladaP == ARQUITETURA_IPV4 :

        return IFACE_1

      elif(arquiteturaEncapsuladaP == ARQUITETURA_ETARCH) :   

        return IFACE_1

      elif(arquiteturaEncapsuladaP == ARQUITETURA_NG) :   

        return IFACE_1
	
    return -1

def handle_pkt(pkt):

  if Ether in pkt:

    if pkt[Ether].type == 0x800:
      pass

    elif pkt[Ether].type == 0x880 and pkt[Ether].dst == '44:54:53:00:00:00' :      

      print('sending packet ETARCH to eth1')

      ifaceChoice = choiceIface(pkt[Ether].type, -1)
      pkt.show2()	   		
      if ifaceChoice != -1 :	          
        sendp(pkt, iface=ifaceChoice, verbose=False)
      else :
        print("ERRO! Primitiva de controle nao enviada!")       

    elif pkt[Ether].type == 0x900 and pkt[Ether].src == '46:49:58:50:00:00' :

      print('sending packet FIXP to eth1')

      rawData = json.loads(pkt[Raw].load)	
      ifaceChoice = choiceIface(pkt[Ether].type, rawData[0][0])
      pkt.show2()	   		
      if ifaceChoice != -1 :	          
        sendp(pkt, iface=ifaceChoice, verbose=False)
      else :
        print("ERRO! Primitiva de controle nao enviada!") 

def main():

  print "sniffing eth0"
  #sys.stdout.flush()
  #contrario. pacotes que estao saindo: filter='outbound'
  #sniff(iface='eth0', prn = lambda x: handle_pkt(x), filter='inbound')
  pkt = Ether(src="ab:ab:ab:ab:ab:ab", dst='ff:ff:ff:ff:ff:ff', type = 0X901)
  sendp(pkt, iface='eth0', verbose=False)

if __name__ == '__main__':
    main()
