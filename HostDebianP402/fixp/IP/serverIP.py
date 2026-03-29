#!/usr/bin/env python

#SIMULACAO DO SERVER

import sys
import struct
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

ARQUITETURA_IPV4 = 0x0800 

IFACE_P          = 'eth0'

contador         = 1

IP_DST           = '192.168.171.104' #IP DO HOST 01
IP_SRC           = '192.168.184.102' #IP DO HOST 02

UDP_SPORT_VIDEO  = 8554 #porta do video fmm
 					
MAC_DST          = '08:00:27:47:2b:1d'  #MAC DO HOST 01
MAC_SRC          = '08:00:27:a2:64:af'  #MAC DO HOST 02

SPORT            = 5170  #porta de origem
DPORT            = 2170  #porta de destino

PRO_TRA          = 0x11 #protocolo de transporte udp

def primitiveSend(requestNumberP):

  pkt = Ether(dst=MAC_DST, src=MAC_SRC, type=0x800)

  pkt = pkt / IP(dst=IP_DST, src=IP_SRC, proto=PRO_TRA)

  pkt = pkt / UDP(sport=SPORT, dport=DPORT)

  pkt = pkt / Raw(load = '*** Envio da resposta da requisicao IP/UDP numero '+ str(requestNumberP) + '.')

  sendp(pkt, iface=IFACE_P, verbose=False)

def retornaNumeroRequisicao(result, caractP="handle", simP = ".") :

  retorno = list()

  resultado = result.lower()

  if(resultado.find("erro") != -1 or resultado.find("invalid") != -1) :   
    return([-1])

  while(resultado.find(caractP) != -1) :

    if(resultado.find(simP) > resultado.find(caractP)) :

      retorno.append(int(resultado[(resultado.find(caractP)+len(caractP)+1):resultado.find(simP)]))

    resultado = resultado[(resultado.find(simP)+1):len(resultado)]

  return retorno   

def handle_pkt(pkt):

  if Ether in pkt:

    if pkt[Ether].type == ARQUITETURA_IPV4:
      
      if pkt[IP].dst == IP_SRC and pkt[IP].proto == PRO_TRA :#and pkt[UDP].dport != UDP_SPORT_VIDEO:

	requestNumber = retornaNumeroRequisicao(pkt[Raw].load, 'numero')[0]

        print('***Requisicao numero ',requestNumber, '.')
        pkt.show2()    	
	print('*** Comeco da resposta ')
	primitiveSend(requestNumber)
        print('*** Fim da resposta ')
	print('')

def main():

  print("sniffing ", IFACE_P)

  sys.stdout.flush()  

  sniff(iface=IFACE_P, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
  main()
