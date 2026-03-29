#!/usr/bin/env python

#CONTROLADOR IP

#PARTE-SE DO PRESSUPOSTO QUE A COMUNICACAO SO ACONTECA CASO A MAQUINA (MAC) SEJA REGISTRADA ANTERIOMENTE NO CONTROLADOR
#O MOTIVO E QUE O CONTROLADOR NAO PODE RECEBER TODOS OS PROTOCOLOS IP QUE TRAFEGAM PELA REDE

import sys
import struct
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

ARQUITETURA_IPV4          = 0x0800
ARQUITETURA_IPV4_S        = "\x08\x00"

ARQUITETURA_FIXP_FM_IPV4  = 0x0809 #fixp flow_mod IPv4

ARQUITETURA_FIXP          = 0x0900

ARQUITETURA_IPV4_D        = 2048

IFACE_P                   = 'eth0'

TABLE_ADD_MODIFY          = 1

STATUS_SUCESSO            = 0

#s01; 02; etc
SWITCHES_REGISTRADOS_H    = ['\x73\x30\x31',
			     '\x73\x30\x32', 
			     '\x73\x30\x33', 
			     '\x73\x30\x34', 
			     '\x73\x30\x35']

THRIFT_PORTS_REGISTRADAS  = ['9090']

MAC_SWITCH_P4             = '46:49:58:50:00:00'

NOME_TABELA_IP            = "FIXP_Switch_Ingress.ipv4_forward"
NOME_ACAO_IP              = "FIXP_Switch_Ingress.ipv4_SetSpec"

#ABAIXO, LISTAS DE REGISTRO DE HOSTS E PROTOCOLOS QUE ESTAO REGISTRADOS NO CONTROLADOR
MACS_REGISTRADOS          = ['08:00:27:c8:f9:0d', 
		             '08:00:27:6f:bd:91']

REDE_FISICA_ATUAL         = 4 #pode ter varias, apesar do roteamento ser manual

REDE_FISICA_VERSAO_3      = 3
REDE_FISICA_VERSAO_4      = 4

primitivasReinseridas = dict()
numeroRequisicaoFIXP  = 1

def primitiveSend(pktP, arquiteturaEncapsuladaP, switchP, portaP) : #PACKET_OUT

  pktAux = Ether(dst=pktP[Ether].dst, src=pktP[Ether].src, type=ARQUITETURA_FIXP)

  pktAux = pktAux / Raw(load = arquiteturaEncapsuladaP + str(switchP) + str(portaP))

  pktAux = pktAux / IP(dst=pktP[IP].dst, src=pktP[IP].src, proto=pktP[IP].proto)

  pktAux = pktAux / UDP(sport=pktP[UDP].sport, dport=pktP[UDP].dport)

  pktAux = pktAux / Raw(load = str(pktP[Raw].load))

  #pktAux[Raw].load = )  

  print("pacote armazenado")
  pktP.show2()

  #pktP[Ether].type = 0x809
  #pktP[Raw].load = str(switchP) + str(portaP) + str(pktP[Raw].load)
  
  print("pacote modificado 1")
  pktAux.show2()
  
  #sendp(pktP, iface=IFACE_P, verbose=False)
  sendp(pktAux, iface=IFACE_P, verbose=False)
  #exit(1)


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


def fixpPrimitiveSend(sendDataP) : ##FLOW_MOD

  jasonString = '/*' + json.dumps(sendDataP) + '*/'

  pkt = Ether(dst='FIXP\x00\x00', src='IPCONT', type=ARQUITETURA_FIXP)

  pkt = pkt / Raw(load = jasonString)

  sendp(pkt, iface=IFACE_P, verbose=False)

def roteamentoRedeFisica(dstIpP, redeFisicaP) :

  #so server para 1 switch. depois tem que modificar												 
  #o certo seria [("s01", 7, 9090)]	

  if redeFisicaP == REDE_FISICA_VERSAO_3 : #Primeira versao de rede com apenas 1 switch

    if dstIpP == "192.168.211.102" :
	
      return ("s01", 6, 9090)	#switch, numero de porta, thrift-port
	
    elif dstIpP == "192.168.221.102" :

      return ("s01", 7, 9090)	#switch, numero de porta, thrift-port

  elif redeFisicaP == REDE_FISICA_VERSAO_4 : #Primeira versao de rede com apenas 1 switch

    if dstIpP == "192.168.211.102" :
	
      return ("s01", 6, 9090)	#switch, numero de porta, thrift-port
	
    elif dstIpP == "192.168.221.102" :

      return ("s01", 7, 9090)	#switch, numero de porta, thrift-port

	
    return (-1, -1, -1)

def handle_pkt(pkt):

  global primitivasReinseridas
  global numeroRequisicaoFIXP

  if Ether in pkt:

    if pkt[Ether].type == ARQUITETURA_IPV4 :
      
      if pkt[Ether].src in MACS_REGISTRADOS and pkt[Raw].load[0:3] not in SWITCHES_REGISTRADOS_H :

        print('***Recebimento da requisicao IP/UDP numero ' + str(retornaNumeroRequisicao(pkt[Raw].load, 'numero')[0]) + '.')
        pkt.show2()    		

        (switch, porta, thiftPort) = roteamentoRedeFisica(pkt[IP].dst, REDE_FISICA_ATUAL) 

        if(switch != -1) :

          sendData = list()

  	  sendData.append([ARQUITETURA_IPV4_D, 
	  		   numeroRequisicaoFIXP,
			   switch,
			   thiftPort,
			   TABLE_ADD_MODIFY,
			   NOME_TABELA_IP,
			   [pkt[IP].dst],
			   [NOME_ACAO_IP],
			   [[porta]],
			   0])

          print('***Comeco de envio do protocolo FIXP ')	
          fixpPrimitiveSend(sendData)
	  print('***Fim de envio do protocolo FIXP. Requisicao numero ' + str(numeroRequisicaoFIXP))	

          primitivasReinseridas[numeroRequisicaoFIXP] = pkt  
  	  
          print('')
          numeroRequisicaoFIXP += 1

        else :
 
          print("Roteamento invalido")
        
    elif (pkt[Ether].type == ARQUITETURA_FIXP) and pkt[Ether].src == MAC_SWITCH_P4 : #VEIO DO SWITCH P4 (EVITAR LOOP) : 
										     #MAC 'FIXP' JA ESTA SENDO TESTADO NA INTERFACE
      
      rawData = json.loads(pkt[Raw].load[(pkt[Raw].load.find('/*')+2):pkt[Raw].load.find('*/')])       

      if len(rawData) == 1 :	

        if(rawData[0][0] == ARQUITETURA_IPV4) :

          if(rawData[0][4] == TABLE_ADD_MODIFY) :

            print('***Inicio do recebimento da resposta da requisicao FIXP numero ' + str(rawData[0][1]))
            pkt.show2()    	
	    print('***Comeco da analise de resposta')	

	    if(rawData[0][6] == STATUS_SUCESSO) :
              
	      if(rawData[0][1] in primitivasReinseridas.keys()) :	

		reinsertionPkt = primitivasReinseridas[rawData[0][1]]

	        (switch, porta, thiftPort) = roteamentoRedeFisica(reinsertionPkt[IP].dst, REDE_FISICA_VERSAO_3) 	
			
  	        primitiveSend(reinsertionPkt, #pacote de reinsercao do dado
			      ARQUITETURA_IPV4_S, 
			      struct.pack('3s', switch.encode('utf-8')), #switch
			      struct.pack('>H', porta)) #porta de saida o pacote (PACKET_OUT)

                del(primitivasReinseridas[rawData[0][1]]) #atualiza estrutura de dados

                print("A operacao foi realizada com sucesso!")

              else :  

	        print('Sequencia de primitiva invalida') 		

            else :
              print("A operacao nao foi realizada!")     

            print('*** Fim da analise de resposta.')
	    print('')	    

          else:

            print('O comando recebido e invalido para essa arquitetura')

        else :

          print('Arquitetura invalida') 

    else:

      print('Pacote IP recebido nao esta configurado pelo controlador')        


def main():

  print("sniffing ", IFACE_P)

  sys.stdout.flush()  

  sniff(iface=IFACE_P, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
  main()
