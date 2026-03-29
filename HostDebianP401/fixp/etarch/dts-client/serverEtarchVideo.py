#envia video para cliente / host 06

#!/usr/bin/env python

#SIMULACAO DO SERVER

#python serverEtarchVideo w1 -> envia o streaming de video para consumo do cliente no workspace w1
#python serverEtarchVideo 500 w1 -> envia 500 pacotes de streaming para colhimento de metricas no cliente (worspace w1)

import sys
import struct
import os
import json
import hashlib


from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, send, get_if_addr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from datetime import datetime, timedelta#, timezone, 

ARQUITETURA_IPV4 = 0x0800

ARQUITETURA_ETARCH = 0x0880

IFACE_P_ESCUTA   = 'eth1'
IFACE_P_ENVIO    = 'eth0'

CHAVE_WORKSPACE = '-1'

contador         = 1

IP_DST           =  '192.168.184.102'   #IP DE DESTINO HOST 02 (POR ENQUANTO)
IP_SRC           =  '-1'                #IP DE ORIGEM PEGA-LO EM TEMPO DE EXECUCAO

MAC_DST          = '08:00:27:74:42:08'  #MAC DO HOST 02
MAC_SRC          = '-1'  #MAC DE ORIGEM PEGA-LO EM TEMPO DE EXECUCAO

SPORT            = 2170  #porta de origem
DPORT            = 5170  #porta de destino

PRO_TRA          = 0x11 #protocolo de transporte udp

VIDEO_PORT       = 8554 #porta do video

id = 1

linhaContador    = 0;

EXECUTA          = -1
EXECUTA_STREAMING_VIDEO_CONSUMO = 1
EXECUTA_STREAMING_VIDEO_TESTES = 2

contadorEscuta = -1

listaStreaming = list()

def primitiveSend(pkt):

  global MAC_SRC
  global IP_SRC
  global CHAVE_WORKSPACE

  pkt_envio = Ether(dst=CHAVE_WORKSPACE, src=MAC_SRC, type=ARQUITETURA_ETARCH) #/ pkt
  #pkt_envio = pkt_envio / Ether(dst=MAC_DST, src=MAC_SRC, type=ARQUITETURA_IPV4)

  pkt_envio = pkt_envio / IP(tos=pkt[IP].tos, id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag, ttl=pkt[IP].ttl, proto=pkt[IP].proto, dst=IP_DST, src=IP_SRC)

  pkt_envio = pkt_envio / UDP(sport=pkt[IP].sport, dport=pkt[IP].dport)

  pkt_envio = pkt_envio / Raw(load = pkt[Raw].load)
  #pkt_envio[0].show()  

  if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :
    #print("Raw..: ", pkt_envio[Raw].load)
    #print("Lng..: ", len(pkt_envio[Raw].load))
    resp = hashlib.sha256(pkt_envio[Raw].load).digest()[:12]
    stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in resp[:12]]).strip()
    #print("hash: ", stringPacoteId)
    #exit(1)

  data_atual = datetime.now()
  sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)

  if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :      
    atualizaListaStreaming(pkt_envio, data_atual, stringPacoteId)

def atualizaListaStreaming(pktEnvioP, dataAtualP, stringPacoteIdP) :

  global listaStreaming
  global linhaContador

  linhaContador+=1;
    
  listaStreaming.append([str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktEnvioP)), ";", "\n"])


def retornaNumeroRequisicao(result, caractP="handle", simP = ".") :

  retorno = list()

  resultado = result.lower()

  if(resultado.find("erro") != -1 or resultado.find("invalid") != -1) :   
    return([-1])

  while(resultado.find(caractP) != -1) :

    if(resultado.find(simP) > resultado.find(caractP)) :

      retorno.append(int(resultado[(resultado.find(caractP)+len(caractP)+1):resultado.find(simP)]))

    pkt[Ether].dst = MAC_DST
    resultado = resultado[(resultado.find(simP)+1):len(resultado)]

  return retorno   

def handle_pkt(pkt):

  #if Ether in pkt:

    #if pkt[Ether].type == ARQUITETURA_IPV4:
      
      #if pkt[IP].dst == IP_DST and pkt[IP].proto == PRO_TRA:

	#requestNumber = retornaNumeroRequisicao(pkt[Raw].load, 'numero')[0]

        #print('***Requisicao numero ',requestNumber, '.')
        #pkt.show2()    	
	#print('*** Comeco da resposta ')
	#primitiveSend(requestNumber)
        #print('*** Fim da resposta ')
	#print('')

  #primitiveSend(pkt)
  global id  
  print("passou aqui ", id)
  id+=1
  
  #pkt[Ether].dst = MAC_DST
  #sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)
  primitiveSend(pkt)

def gravaStreamingArquivo() :
  file = open("envioEtarchPacotesMetricaVideo.csv","w")
   
  for elementosLista in listaStreaming :
    file.writelines(elementosLista)      

  file.close()

def main():

  global EXECUTA
  global CONTADOR_ESCUTA
  global MAC_SRC
  global IP_SRC
  global CHAVE_WORKSPACE

  print "\n********INICIO DADOS DO PROGRAMA"
  print ("")
  print "Nome do programa........................: " + sys.argv[0]

  if(len(sys.argv) == 2) :
    print "  Primeiro parametro (execucao).......dd: Streaming de video para consumo - Server"
    EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO
    CHAVE_WORKSPACE = ":".join("{:02x}".format(ord(c)) for c in hashlib.sha256(sys.argv[1]).digest()[:6])
    
  elif (len(sys.argv) == 3) :
    print "  Primeiro parametro (execucao)...........: Streaming de video para testes - Server"
    EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES
    CONTADOR_ESCUTA = int(sys.argv[1])
    CHAVE_WORKSPACE = ":".join("{:02x}".format(ord(c)) for c in hashlib.sha256(sys.argv[2]).digest()[:6])
  else :
    print("Erro! Parametros invalidos")
    exit(1)

  print("  sniffing ", IFACE_P_ESCUTA)
  print "\n********FIM DOS DADOS DO PROGRAMA"

  print("")
  print "\n********INICIO DA EXECUCAO"
  print("")

  sys.stdout.flush() 

  IP_SRC  = get_if_addr  (IFACE_P_ENVIO)
  MAC_SRC = get_if_hwaddr(IFACE_P_ENVIO)

  #filtro do scapy precisa do tcpdump para funcionar.
  filtro = 'ether proto ' + str(ARQUITETURA_IPV4) + ' and port ' + str(VIDEO_PORT) + ' and host ' + IP_DST + ' or ' + IP_SRC 
  #print("filro..:", filtro)

  if EXECUTA == EXECUTA_STREAMING_VIDEO_CONSUMO :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x))
  elif EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x), count = CONTADOR_ESCUTA)
    gravaStreamingArquivo();
  else :
    print("**************") 
    print("  FIM DE PROGRAMA - ERRO DE EXECUCAO!!!")
    print("**************") 

if __name__ == '__main__':
  main()
