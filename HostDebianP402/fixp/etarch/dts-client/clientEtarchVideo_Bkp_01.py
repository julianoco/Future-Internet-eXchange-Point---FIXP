#envia video para cliente / host 06

#!/usr/bin/env python

#SIMULACAO DO SERVER

#python clientIPVideo -> escuta porta indefinidamente
#python clientIPVideo 500 -> escuta um numero de pacotes definido para colhimento de informacoes para metricas
#o tamanho dos pacotes vai depender dos parametros passados no ffmpeg			    

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

ARQUITETURA_IPV4   = 0x0800
ARQUITETURA_ETARCH = 0x0880

IFACE_P_ESCUTA   = 'eth0'
IFACE_P_ENVIO    = 'eth0'

IP_DST           =  '-1'
IP_SRC           =  '-1'

MAC_DST          = '-1'  #MAC DO HOST 
MAC_SRC          = '-1'  #MAC DO HOST 

SPORT            = 2170  #porta de origem
DPORT            = 5170  #porta de destino

PRO_TRA          = 0x11 #protocolo de transporte udp

VIDEO_PORT       = 8554 #porta do video

id = 1

linhaContador    = 0;

EXECUTA          = -1
EXECUTA_STREAMING_VIDEO_CONSUMO = 1
EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES = 2

listaStreaming = list()

def primitiveListening(pkt, dataAtualP):
  #data_atual = datetime.now()
  resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in resp[:12]]).strip()
  #print("hash: ", stringPacoteId)
  #exit(1)
  #sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)    
  atualizaListaStreaming(pkt, dataAtualP, stringPacoteId)

def atualizaListaStreaming(pktP, dataAtualP, stringPacoteIdP) :

  global listaStreaming
  global linhaContador

  linhaContador+=1;
    
  listaStreaming.append([str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktP)), ";", "\n"])


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

def primitiveSend(pkt):

  global MAC_SRC
  global IP_SRC
  global CHAVE_WORKSPACE

  #pkt_envio = Ether(dst=MAC_SRC, src=pkt[Ether].src, type=ARQUITETURA_IPV4) #/ pkt
  #para executar de dentro do host, ou seja, o proprio hosto mandando para host, duas coisas e necessaria para que o ffmplay abra
  #primeiro. o mac tem que ir zerado, o ip pouco importa
  #segundo. o envio tem que ocorrer para a inteface de loopback, ela tem a responsabilidade de mandar pacote para dentro do host para host
  #quando o host e o propra maquina, ou seja, maquina mandando mensagem para propria maquina
  #tudo ocorreu bem, abaixo fazemos o desencapsulamento das informacoes.
  pkt_envio = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=ARQUITETURA_IPV4) #/ pkt

  #monta cabecalho IP que esta encapsulado (de 20 bytes)
  pkt_envio = pkt_envio / IP(pkt[Raw].load[0:20])

  pkt_envio = pkt_envio / UDP(pkt[Raw].load[20:28])

  pkt_envio = pkt_envio / Raw(pkt[Raw].load[28:])

  data_atual = datetime.now()
  #sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)
  sendp(pkt_envio, iface="lo", verbose=False)

  #if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :      
  #  atualizaListaStreaming(pkt_envio, data_atual, stringPacoteId) 

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
  print("Requisicao de video ", id)
  id+=1
  
  #pkt[Ether].dst = MAC_DST
  #sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)
  dataAtual = datetime.now()
  primitiveSend(pkt)    
  if (EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES) : 
    primitiveListening(pkt, dataAtual)

def gravaStreamingArquivo() :
  file = open("recebimentoPacotesMetricaVideo.csv","w")
   
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
  print("  Nome do programa........................: ") + sys.argv[0]

  if(len(sys.argv) == 1) :
    print "  Primeiro parametro (execucao).........: Streaming de video para consumo - Cliente"
    print ("  Contador: Sem contador")
    EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO
  else :
    print "  Primeiro parametro (execucao).........: Streaming de video para testes - Cliente"
    print ("  Contador: ", sys.argv[1])
    CONTADOR_ESCUTA = int(sys.argv[1])
    EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES

  print("  sniffing ", IFACE_P_ESCUTA)
  print "\n********FIM DOS DADOS DO PROGRAMA"

  print("")
  print "\n********INICIO DA EXECUCAO"
  print("")

  sys.stdout.flush() 

  IP_SRC  = get_if_addr  (IFACE_P_ENVIO)
  MAC_SRC = get_if_hwaddr(IFACE_P_ENVIO)

  filtro = 'ether proto ' + str(ARQUITETURA_ETARCH)

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
