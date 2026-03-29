exit#!/usr/bin/env python
import sys
import struct
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

#configuracao dos etherType aceitas pela FIXP
ARQUITETURA_IPV4   	 = 0x0800 
ARQUITETURA_ETARCH 	 = 0x0880 
ARQUITETURA_NG_SIMULACAO = 0x1235 
ARQUITETURA_FIXP   	 = 0x0900
ARQUITETURA_NG     	 = 0x1234  

#Configuracao das interfaces de transmissao para os controladores
IFACE_0           = 'eth0'
IFACE_1           = 'eth1'
IFACE_2           = 'eth2'
IFACE_3           = 'eth3'
IFACE_4           = 'eth4'
IFACE_5           = 'eth5'
IFACE_6           = 'eth6'
IFACE_7           = 'eth7'
IFACE_8           = 'eth8'

I_FACE_P          = 'eth1' #interface padrao, no caso de flood de controle (PARA FLOOD_CONTROLE = 1)

FLOOD_CONTROLE    = 0  #1(APENAS UMA INTERFACE SERA CONFIGURADA -> IFACE_P PARA TODOS OS CONTROLADORES
		       #0(VARIAS INTERFACES SERAO CONFIGURADAS. 1 PARA CADA CONTROLADOR

MACS_REGISTRADOS  = ['08:00:27:a2:64:af', 
		     '08:00:27:47:2b:1d']

I_FACES_SNIFF  = [IFACE_0, IFACE_5, IFACE_6, IFACE_7, IFACE_8] #para a versao 04 (CONSTANTE)

REDE_FISICA_ATUAL = 4
REDE_FISICA_VERSAO_003 = 3
REDE_FISICA_VERSAO_004 = 4

def choiceIfaceSniff(redeFisicaP = REDE_FISICA_ATUAL) :

    if(redeFisicaP == REDE_FISICA_VERSAO_004) :
    
        return [IFACE_0, IFACE_5, IFACE_6, IFACE_7, IFACE_8]      

    

def choiceIface(arquiteturaPrincipalP, arquiteturaEncapsuladaP, redeFisicaP = REDE_FISICA_ATUAL) :

    #essa funcao sera desnecessaria, pois as primitivas irao apenas para uma interface

    #caso tenha varias interfaces, o ideal e uma interface para varios switches

    if(redeFisicaP == REDE_FISICA_VERSAO_003) :

	    if FLOOD_CONTROLE == 1 :      

	      if(arquiteturaPrincipalP != ARQUITETURA_FIXP) :

		if arquiteturaPrincipalP in [ARQUITETURA_IPV4,
		  			     ARQUITETURA_ETARCH,
					     ARQUITETURA_NG,
					     ARQUITETURA_NG_SIMULACAO] :

		  return I_FACE_P

	      else :

		if arquiteturaEncapsuladaP in [ARQUITETURA_IPV4,
		  			       ARQUITETURA_ETARCH,
					       ARQUITETURA_NG,
					       ARQUITETURA_NG_SIMULACAO] :


		  return I_FACE_P

	    else :

	      if(arquiteturaPrincipalP != ARQUITETURA_FIXP) :

		if arquiteturaPrincipalP == ARQUITETURA_IPV4 :

		  return IFACE_4 

		elif(arquiteturaPrincipalP == ARQUITETURA_ETARCH) :   

		  return IFACE_1

		elif(arquiteturaPrincipalP == ARQUITETURA_NG) :   

		  pass #configurar

		elif(arquiteturaPrincipalP == ARQUITETURA_NG_SIMULACAO) :   

		  return IFACE_3

	      else :

		if arquiteturaEncapsuladaP == ARQUITETURA_IPV4 :

		  return IFACE_4 

		elif(arquiteturaEncapsuladaP == ARQUITETURA_ETARCH) :   

		  return IFACE_1

		elif(arquiteturaEncapsuladaP == ARQUITETURA_NG) :   

		  pass #configurar
	
		elif(arquiteturaEncapsuladaP == ARQUITETURA_NG_SIMULACAO) :   

		  return IFACE_3

    elif(redeFisicaP == REDE_FISICA_VERSAO_004) :

	    if FLOOD_CONTROLE == 1 :      

	      if(arquiteturaPrincipalP != ARQUITETURA_FIXP) :

		if arquiteturaPrincipalP in [ARQUITETURA_IPV4,
		  			     ARQUITETURA_ETARCH,
					     ARQUITETURA_NG,
					     ARQUITETURA_NG_SIMULACAO] :

		  return I_FACE_P

	      else :

		if arquiteturaEncapsuladaP in [ARQUITETURA_IPV4,
		  			       ARQUITETURA_ETARCH,
					       ARQUITETURA_NG,
					       ARQUITETURA_NG_SIMULACAO] :


		  return I_FACE_P

	    else :

	      if(arquiteturaPrincipalP != ARQUITETURA_FIXP) :

		if arquiteturaPrincipalP == ARQUITETURA_IPV4 :

		  return IFACE_4 

		elif(arquiteturaPrincipalP == ARQUITETURA_ETARCH) :   

		  return IFACE_1

		elif(arquiteturaPrincipalP == ARQUITETURA_NG) :   

		  pass #configurar

		elif(arquiteturaPrincipalP == ARQUITETURA_NG_SIMULACAO) :   

		  return IFACE_3

	      else :

		if arquiteturaEncapsuladaP == ARQUITETURA_IPV4 :

		  return IFACE_4 

		elif(arquiteturaEncapsuladaP == ARQUITETURA_ETARCH) :   

		  return IFACE_1

		elif(arquiteturaEncapsuladaP == ARQUITETURA_NG) :   

		  pass #configurar
	
		elif(arquiteturaEncapsuladaP == ARQUITETURA_NG_SIMULACAO) :   

		  return IFACE_3

    return -1

def handle_pkt(pkt):

  if Ether in pkt:

    if pkt[Ether].type == ARQUITETURA_IPV4 and pkt[Ether].src in MACS_REGISTRADOS:

      ifaceChoice = choiceIface(pkt[Ether].type, -1)
      print('sending packet IPv4 to ', ifaceChoice)
      pkt.show2()	   		
      if ifaceChoice != -1 :	          
        sendp(pkt, iface=ifaceChoice, verbose=False)
      else :
        print("ERRO! Primitiva de controle nao enviada!")       


    elif pkt[Ether].type == ARQUITETURA_ETARCH and pkt[Ether].dst == '44:54:53:00:00:00' :      
      
      ifaceChoice = choiceIface(pkt[Ether].type, -1)
      print('sending packet ETARCH to ', ifaceChoice)
      pkt.show2()	   		
      if ifaceChoice != -1 :	          
        sendp(pkt, iface=ifaceChoice, verbose=False)
      else :
        print("ERRO! Primitiva de controle nao enviada!")       

    elif pkt[Ether].type == ARQUITETURA_NG_SIMULACAO and pkt[Ether].dst == '44:54:53:00:00:00' :      
      
      ifaceChoice = choiceIface(pkt[Ether].type, -1)
      print('sending packet NOVA GENESIS (SIMULATION) to ', ifaceChoice)
      pkt.show2()	   		
      if ifaceChoice != -1 :	          
        sendp(pkt, iface=ifaceChoice, verbose=False)
      else :
        print("ERRO! Primitiva de controle nao enviada!")       

    elif pkt[Ether].type == ARQUITETURA_FIXP and pkt[Ether].src == '46:49:58:50:00:00' : #FIXP FLOWMOD
      
      #pkt.show2()		   		
      #para ethernet/nova genesis
      #rawData = json.loads(pkt[Raw].load) 
      #para IP
      #rawData = json.loads(pkt[Raw].load[0:pkt[Raw].load.find('\x00')])

      rawData = json.loads(pkt[Raw].load[(pkt[Raw].load.find('/*')+2):pkt[Raw].load.find('*/')]) 

      if len(rawData) != 0 :
        if len(rawData[0]) != 0 :
          ifaceChoice = choiceIface(pkt[Ether].type, rawData[0][0])
          print('sending packet FIXP to ', ifaceChoice)
          pkt.show2()	   		
          if ifaceChoice != -1 :	          
            sendp(pkt, iface=ifaceChoice, verbose=False)
          else :
            print("ERRO! Primitiva de controle nao enviada!") 
        else : 
          print('Erro! Primitiva nao enviada. Ha inconsistencia dos dados recebidos! ')
          pkt.show2()	   		     
      else :
        print('Erro! Primitiva nao enviada. Ha inconsistencia dos dados recebidos! ')
        pkt.show2()	   		


def main():

  I_FACES_SNIFF = choiceIfaceSniff(REDE_FISICA_VERSAO_004)

  print("sniffing interfaces dos switches : ", I_FACES_SNIFF)
  sys.stdout.flush()

  #contrario. pacotes que estao saindo: filter='outbound' #nao funcionou
  sniff(iface=I_FACES_SNIFF, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
