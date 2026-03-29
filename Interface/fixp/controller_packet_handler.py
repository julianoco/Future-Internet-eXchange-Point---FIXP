#!/usr/bin/env python
import sys
import struct
import os
import socket
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

#0x809 -> FIXP PARA PACKET_OUT PARA ARQUITETURA IP

ARQUITETURA_IPV4         = 0x0800
ARQUITETURA_IPV4_FIXP    = 0x0890
ARQUITETURA_ETARCH       = 0x0880 	   #PACKET_OUT
ARQUITETURA_FIXP         = 0x0900 	   #PACKET_MODIFY  /* FOR ALL ARCHITECTURES */
ARQUITETURA_NG_SIMULACAO = 0x1235 	   #SIMULACAO NOVA GENESIS

ARQUITETURA_IPV4_S         = '\x08\x00'
ARQUITETURA_ETARCH_S       = '\x08\x80' 	   #PACKET_OUT
ARQUITETURA_FIXP_S         = '\x09\x00' 	   #PACKET_MODIFY  /* FOR ALL ARCHITECTURES */
ARQUITETURA_NG_SIMULACAO_S = '\x12\x35' 	   #SIMULACAO NOVA GENESIS

I_FACE_0 = 'eth0'
I_FACE_1 = 'eth1' #ETARCH (porta 01)
I_FACE_3 = 'eth3' #simulacao nova genesis (porta 03)
I_FACE_4 = 'eth4' #simulacao controlador IP (porta 04)
I_FACE_5 = 'eth5'
I_FACE_6 = 'eth6'
I_FACE_7 = 'eth7'
I_FACE_8 = 'eth8'

I_FACE_P = 'eth1' #interface padrao, no caso de flood de controle (PARA FLOOD_CONTROLE = 1)

FLOOD_CONTROLE = 0  #1(APENAS UMA INTERFACE SERA CONFIGURADA -> IFACE_P PARA TODOS OS CONTROLADORES
		    #0(VARIAS INTERFACES SERAO CONFIGURADAS. 1 PARA CADA CONTROLADOR

I_FACES_SNIFF  = [I_FACE_1, I_FACE_3, I_FACE_4] #interfaces para FLOOD_CONTROLE = 0
I_FACE_P_SNIFF = [I_FACE_P]

MACS_REGISTRADOS  = ['08:00:27:a2:64:af', 
		     '08:00:27:47:2b:1d']

REDE_FISICA_ATUAL = 4
REDE_FISICA_VERSAO_003 = 3
REDE_FISICA_VERSAO_004 = 4


#TODO: define data received

#no caso de cada switch estar acoplado a uma porta
#no entanto, tem que ser uma porta so. Nao faz sentido muitas interfaces

def choiceIface(arquitetura, switch, redeFisicaP = REDE_FISICA_ATUAL) :

    #essa funcao sera desnecessaria, pois as primitivas irao apenas para uma interface

    #caso tenha varias interfaces, o ideal e uma interface para varios switches

    #configuracao de redes com topologias distintas
    if(redeFisicaP == REDE_FISICA_VERSAO_003) :
	    
	    #nao faz sentido cada arqutietura nomear os switches da topologia, mas vou fazer assim	    
	    #porque os desenvolvimentos podem estar ocorrendo em faculdades distintas
	    #cada qual com suas topologias	

	    if(arquitetura == ARQUITETURA_ETARCH) :      	
  	      if switch == "\x73\x30\x31" : #s01
	        return I_FACE_0

	    elif(arquitetura == ARQUITETURA_FIXP) :      	
	      if switch == "\x73\x30\x31" : #s01
	    	return I_FACE_0

	    elif(arquitetura == ARQUITETURA_IPV4) :      	
	      if switch == "\x73\x30\x31" : #s01
	    	return I_FACE_0

    if(redeFisicaP == REDE_FISICA_VERSAO_004) :
	    
	    #nao faz sentido cada arqutietura nomear os switches da topologia, mas vou fazer assim	    
	    #porque os desenvolvimentos podem estar ocorrendo em faculdades distintas
	    #cada qual com suas topologias	

	    if(arquitetura == ARQUITETURA_ETARCH) :      	
  	      if switch == "\x73\x30\x31" : #s01
	        return I_FACE_0
  	      elif switch == "\x73\x30\x32" : #s02
	        return I_FACE_5
  	      elif switch == "\x73\x30\x33" : #s03
	        return I_FACE_6
  	      elif switch == "\x73\x30\x34" : #s04
	        return I_FACE_7
  	      elif switch == "\x73\x30\x35" : #s05
	        return I_FACE_8

	    elif(arquitetura == ARQUITETURA_FIXP) :      	
	      if switch == "\x73\x30\x31" : #s01
	    	return I_FACE_0
  	      elif switch == "\x73\x30\x32" : #s02
	        return I_FACE_5
  	      elif switch == "\x73\x30\x33" : #s03
	        return I_FACE_6
  	      elif switch == "\x73\x30\x34" : #s04
	        return I_FACE_7
  	      elif switch == "\x73\x30\x35" : #s05
	        return I_FACE_8

	    elif(arquitetura == ARQUITETURA_IPV4) :      	
	      if switch == "\x73\x30\x31" : #s01
	    	return I_FACE_0
  	      elif switch == "\x73\x30\x32" : #s02
	        return I_FACE_5
  	      elif switch == "\x73\x30\x33" : #s03
	        return I_FACE_6
  	      elif switch == "\x73\x30\x34" : #s04
	        return I_FACE_7
  	      elif switch == "\x73\x30\x35" : #s05
	        return I_FACE_8

	
    return -1

def handle_pkt(pkt):

    if Ether in pkt:
	'''
        if pkt[Ether].type == ARQUITETURA_IPV4_FIXP and pkt[Ether].src in MACS_REGISTRADOS : ##TIRAR

   	        if (
		     ( (pkt.sniffed_on == I_FACE_4) and (FLOOD_CONTROLE == 0)) or
		     ( (pkt.sniffed_on == I_FACE_P) and (FLOOD_CONTROLE == 1)) ):

			print("Reinsercao do dado pelo controlador IPv4")

		        pkt.show2()	   		

			print("switch ", pkt[Raw].load[0:3])

			ifaceChoice = choiceIface(ARQUITETURA_IPV4, pkt[Raw].load[0:3])
	
			if ifaceChoice != -1 :	          
	
		          sendp(pkt, iface=ifaceChoice, verbose=False)

			else :

	                  print("ERRO! Primitiva de controle nao enviada!")

		else :

			print("Erro! Inconsistencia no recebimento de primitivas das interfaces. ")

		        pkt.show2()	   		
	'''
	if pkt[Ether].type == ARQUITETURA_ETARCH and pkt[Ether].src == '44:54:53:00:00:00' : #Handshakes Etarch (PACKET_OUT ESPECIFICO DA ETARCH)

   	        if (
		     ( (pkt.sniffed_on == I_FACE_1) and (FLOOD_CONTROLE == 0)) or
		     ( (pkt.sniffed_on == I_FACE_P) and (FLOOD_CONTROLE == 1)) ):

			print("Resposta do controlador ETARCH ")

		        pkt.show2()	   		

			print("switch ", pkt[Raw].load[0:3])

			ifaceChoice = choiceIface(ARQUITETURA_ETARCH, pkt[Raw].load[0:3])
			print('sending packet ETARCH to ', ifaceChoice)
	
			if ifaceChoice != -1 :	          
	
		          sendp(pkt, iface=ifaceChoice, verbose=False)

			else :

	                  print("ERRO! Primitiva de controle nao enviada!")

		else :

			print("Erro! Inconsistencia no recebimento de primitivas das interfaces. ")

		        pkt.show2()	   		

	elif pkt[Ether].type == ARQUITETURA_NG_SIMULACAO and pkt[Ether].src == '44:54:53:00:00:00' : #Handshakes Nova Genesis Simulacao (PACKET_OUT)

   	        if (
		     ( (pkt.sniffed_on == I_FACE_3) and (FLOOD_CONTROLE == 0)) or
		     ( (pkt.sniffed_on == I_FACE_P) and (FLOOD_CONTROLE == 1)) ):

			print("Resposta do controlador NOVA GENESIS SIMULACAO ")		       
			print("switch ", pkt[Raw].load[0:3])
			ifaceChoice = choiceIface(ARQUITETURA_ETARCH, pkt[Raw].load[0:3])
			print('sending packet NOVA GENESIS SIMULACAO to ', ifaceChoice)

			pkt.show2()	   		
	
			if ifaceChoice != -1 :	          
	
		          sendp(pkt, iface=ifaceChoice, verbose=False)

			else :

	                  print("ERRO! Primitiva de controle nao enviada!")

		else :

			print("Erro! Inconsistencia no recebimento de primitivas das interfaces. ")

		        pkt.show2()	   		


	elif pkt[Ether].type == ARQUITETURA_FIXP and pkt[Ether].dst == '46:49:58:50:00:00' : #FIXP (CONTROLLER TO SWITCH) - FLOWMOD

		print("Requisicao de encaminhento (CONTROLLER TO SWITCH) - FLOWMOD")

		#rawData     = json.loads(pkt[Raw].load)
		rawData = json.loads(pkt[Raw].load[(pkt[Raw].load.find('/*')+2):pkt[Raw].load.find('*/')]) #serializacao modificada 

		if len(rawData) != 0 :

			if len(rawData[0]) != 0 :

				switch      = rawData[0][2]	
				arquitetura = rawData[0][0]

				if arquitetura in [ARQUITETURA_ETARCH, ARQUITETURA_NG_SIMULACAO, ARQUITETURA_IPV4] :

					if(
					    (arquitetura == ARQUITETURA_ETARCH and pkt.sniffed_on == I_FACE_1) or
					    (arquitetura == ARQUITETURA_NG_SIMULACAO and pkt.sniffed_on == I_FACE_3) or
					    (arquitetura == ARQUITETURA_IPV4 and pkt.sniffed_on == I_FACE_4) or
					    ((FLOOD_CONTROLE == 1))
					  ) :
				
						print("switch ", switch)
						ifaceChoice = choiceIface(ARQUITETURA_FIXP, switch)				
						print('sending packet FIXP-FLOWMOD to ', ifaceChoice)


			        		pkt.show2()	   		
	
			        		sendp(pkt, iface=ifaceChoice, verbose=False)

					else :

					        print('Erro! Inconsistencia das primitivas recebidas na interface! ')
			        		pkt.show2()	   					

				else :

				        print('Erro! Arquitetura invalida! ')
		        		pkt.show2()	   					


			else:

			        print('Erro! Primitiva nao enviada. Ha inconsistencia dos dados recebidos! ')
	        		pkt.show2()	   					
		
		else:

		        print('Erro! Primitiva nao enviada. Ha inconsistencia dos dados recebidos! ')
        		pkt.show2()	  

	elif pkt[Ether].type == ARQUITETURA_FIXP : #FIXP PACKET OUT GERAL
		
		print("Requisicao PACKET_OUT (CONTROLLER TO SWITCH) ")

		rawData = pkt[Raw].load
		#print("raw data teste: ", rawData)
		#print("raw data teste switch: ", rawData[0:2])
		#print("raw data teste switch: ", rawData[2:5])

		#print("arquitetura IPv4", ARQUITETURA_IPV4_S)
		
		arquitetura      = rawData[0:2]
		switch           = rawData[2:5]

		if arquitetura in [ARQUITETURA_IPV4_S, ARQUITETURA_ETARCH_S, ARQUITETURA_NG_SIMULACAO_S] :

			if(
				(arquitetura == ARQUITETURA_ETARCH_S and pkt.sniffed_on == I_FACE_1) or
				(arquitetura == ARQUITETURA_NG_SIMULACAO_S and pkt.sniffed_on == I_FACE_3) or
			        (arquitetura == ARQUITETURA_IPV4_S and pkt.sniffed_on == I_FACE_4) or
			        ((FLOOD_CONTROLE == 1))
			  ) :
		
                                print("switch ", switch)
				ifaceChoice = choiceIface(ARQUITETURA_FIXP, switch)						
				print('sending packet FIXP-PACKET_OUT to ', ifaceChoice)

	
			        pkt.show2()	   		
	
			        sendp(pkt, iface=ifaceChoice, verbose=False)

			else :

				print('Erro! Inconsistencia das primitivas recebidas na interface! ')
			        pkt.show2()	   					

		else :

			print('Erro! Arquitetura invalida! ')
		        pkt.show2()	

		   					

		
		
		          
def main():

    sys.stdout.flush()

    #contrario. pacotes que estao saindo: filter='outbound'
    if FLOOD_CONTROLE == 0 :        
        print("sniffing interfaces dos controladores : ", I_FACES_SNIFF)
    	sniff(iface=I_FACES_SNIFF, prn = lambda x: handle_pkt(x))
    else :
 	print("sniffing interfaces dos controladores : ", I_FACE_P_SNIFF)
    	sniff(iface=I_FACE_P_SNIFF, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
