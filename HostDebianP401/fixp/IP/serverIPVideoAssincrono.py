#envia video para cliente / host 06

#!/usr/bin/env python

#SIMULACAO DO SERVER

#python serverIPVideo -> envia o streaming de video para consumo do cliente
#python serverIPVideo 500 -> envia 500 pacotes de streaming para colhimento de metricas no cliente

import sys
import struct
import os
import json
import hashlib


from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, send
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from datetime import datetime, timedelta#, timezone, 

ARQUITETURA_IPV4 = 0x0800 

IFACE_P_ESCUTA   = 'eth1'
IFACE_P_ENVIO    = 'eth0'

contador         = 1

IP_DST           =  '192.168.184.102' #IP DO HOST 02 (IP TAMBEM TEM QUE ESTAR CORRETOS, TANTO ORIGEM QUANTO DESTINO SENAO VIDEO NAO FUNCIONA)
IP_SRC           =  '192.168.171.104' #IP DO HOST 01

MAC_DST          = '08:00:27:74:42:08'  #MAC DO HOST 06 PARA FUNCIONAR O VIDEO OS MACS TEM QUE ESTAR CORRETOS
MAC_SRC          = '08:00:27:c9:be:27'  #MAC DO HOST 05 PARA FUNCIONAR O VIDE DA ETARCH TEM QUE ENVIAR PARA A PORTA DE DENTRO DO CLIENTE, ENTAO OS MACS TEM QUE SER ZERADOS

SPORT            = 2170  #porta de origem
DPORT            = 5170  #porta de destino

PRO_TRA          = 0x11 #protocolo de transporte udp

VIDEO_PORT       = 8554 #porta do video

global id 
id = 1

linhaContador    = 0;

EXECUTA          = -1
EXECUTA_STREAMING_VIDEO_CONSUMO = 1
EXECUTA_STREAMING_VIDEO_TESTES = 2

contadorEscuta = -1

listaStreaming = list()

def primitiveSend(pkt):

  global id

  if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :
    resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
    stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()
    #print("hash: ", stringPacoteId)
    #exit(1)

  pkt_envio = Ether(dst=MAC_DST, src=MAC_SRC, type=ARQUITETURA_IPV4)

  #pkt = pkt / IP(tos=pkt[IP].tos, id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag, ttl=pkt[IP].ttl, proto=pkt[IP].proto, dst=IP_DST, src=IP_SRC, proto=PRO_TRA)

  pkt_envio = pkt_envio / IP(tos=pkt[IP].tos, id=pkt[IP].id, flags=pkt[IP].flags, frag=pkt[IP].frag, ttl=pkt[IP].ttl, proto=pkt[IP].proto, dst=IP_DST, src=IP_SRC)

  pkt_envio = pkt_envio / UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)

  #pkt = pkt / Raw(load = '*** Envio da resposta da requisicao IP/UDP numero '+ str(requestNumberP) + '.')

#  if(EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO)
  pkt_envio = pkt_envio / Raw(load = pkt[Raw].load)
#  else
#    pkt_envio = pkt_envio / Raw(load = "/*" + str str()pkt[Raw].load)

  #pkt = pkt / pkt[IP] / pkt[UDP] / pkt[Raw]

  data_atual = datetime.now()

  #modificacao inicio
  #print("Data atual ", data_atual)
  data_atual -= timedelta(seconds=OFFSET)
  #print("Data atual com offset", data_atual) 
  #modificacao fim

  sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)

  if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :      
    atualizaListaStreaming(pkt_envio, data_atual, stringPacoteId)

  print("Envio: Pacote " + str(id), flush=True)  
  id+=1

def atualizaListaStreaming(pktEnvioP, dataAtualP, stringPacoteIdP) :

  global listaStreaming
  global linhaContador

  #linhaContador+=1;    
  #listaStreaming.append([str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktEnvioP)), ";", "\n"])

  linhaContador+=1;

  cabecalhosC = str(pktEnvioP[Ether].dst)+\
                str(pktEnvioP[Ether].src)+\
                str(pktEnvioP[Ether].type)+\
	        str(pktEnvioP[IP].tos)+\
	        str(pktEnvioP[IP].id)+\
	        str(pktEnvioP[IP].flags)+\
	        str(pktEnvioP[IP].frag)+\
	        str(pktEnvioP[IP].dst)+\
		str(pktEnvioP[IP].src)+\
		str(pktEnvioP[IP].proto)+\
		str(pktEnvioP[UDP].sport)+\
		str(pktEnvioP[UDP].dport);

  hashCabecalhoC = hashlib.sha256(cabecalhosC.encode('utf8')).digest()[:12]
  stringPacoteCabecalhoId = ''.join( [ "%02x" % ord( x ) for x in str(hashCabecalhoC[:12])]).strip()                    
    
  listaStreaming.append(["ENVIOS;", #descricao de envio
                         str(linhaContador)+";", #linhaContador
                         stringPacoteIdP + ";",  #identificador do pacote (hash do conteudo do pacote, que e unico por pacote)
                         str(dataAtualP) + ";" , #data atual em datetime e string do envio do pacote
		         str(datetime.timestamp(dataAtualP)) + ";", #data atual em timestamp e string do envio do pacote
		         stringPacoteCabecalhoId + ";", #dados do cabeçalho para verificacao posterior de taxa de erro
                         str(len(pktEnvioP)) + ";", #tamanho do pacote
		         "\n"])

  file = open("EnvioPacotesIPAssincronoServerVideo.csv","a")
  file.writelines(listaStreaming[len(listaStreaming)-1])      
  file.close()


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
  
  #pkt[Ether].dst = MAC_DST
  #sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)
  primitiveSend(pkt)

def gravaStreamingArquivo() :
  #file = open("envioPacotesMetricaVideoServer.csv","w")
  file = open("EnvioPacotesIPAssincronoServerVideo.csv","w")  
  for elementosLista in listaStreaming :
    file.writelines(elementosLista)      
  file.close()

#inicio modificacao
def analisaResultadoPS(resultadoPSP, stringP) :

  retornoValor = -1;
  listaBashPID = list()
  listaBashPID = resultadoPSP.split()
  #print("Lista: ", listaBashPID)
  if stringP in listaBashPID :
    retornoValor = listaBashPID[listaBashPID.index(stringP)-3]      
  return retornoValor
#fim modificacao

def main():

  global EXECUTA
  global CONTADOR
  global CONTADOR_ESCUTA
  global OFFSET
  OFFSET = -1

  print("\n********INICIO DADOS DO PROGRAMA")
  print ("")
  print("Nome do programa........................: " + sys.argv[0])

  if(len(sys.argv) == 1) :
    print("  Primeiro parametro (execucao).......:: Streaming de video para consumo - Server")
    EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO
  else :
    print("  Primeiro parametro (execucao)...........: Streaming de video para testes")
    EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES
    CONTADOR_ESCUTA = int(sys.argv[1])

  print("  sniffing ", IFACE_P_ESCUTA)
  print("\n********FIM DOS DADOS DO PROGRAMA")

  print("")
  print("\n********INICIO DA EXECUCAO")
  print("")

  sys.stdout.flush() 

  #inicio modificacao
  resultPS = os.popen('ps', 'r', 256).read()
  bashPID = analisaResultadoPS(resultPS, "bash")

  arquivo  = open('/root/fixp/NTPClient/offsetNTPDate'+str(bashPID)+'.drift', 'r')
  OFFSET   = float(arquivo.readline())
  arquivo.close
  #fim modificacao

  #filtro = 'ether proto ' + str(ARQUITETURA_IPV4) + ' and port ' + str(VIDEO_PORT) + ' and host ' + IP_DST + ' or ' + IP_SRC 
  filtro = 'ether proto ' + str(ARQUITETURA_IPV4) + ' and port ' + str(VIDEO_PORT) + ' and host ' + IP_DST + ' or ' + IP_SRC + \
                ' and ip proto ' + str(PRO_TRA)


  if EXECUTA == EXECUTA_STREAMING_VIDEO_CONSUMO :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x))
    #gravaStreamingArquivo();
  elif EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x), count = CONTADOR_ESCUTA)
    #gravaStreamingArquivo();
  else :
    print("**************") 
    print("  FIM DE PROGRAMA - ERRO DE EXECUCAO!!!")
    print("**************") 

if __name__ == '__main__':
  main()
