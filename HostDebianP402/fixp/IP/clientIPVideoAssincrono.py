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


from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, send
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from datetime import datetime, timedelta#, timezone, 

ARQUITETURA_IPV4 = 0x0800 

IFACE_P_ESCUTA   = 'eth0'
IFACE_P_ENVIO    = 'eth0'

contador         = 1

IP_DST           =  '192.168.184.102'
IP_SRC           =  '192.168.184.102'

MAC_DST          = '08:00:27:a2:64:af'  #MAC DO HOST 06
MAC_SRC          = '08:00:27:47:2b:1d'  #MAC DO HOST 05

SPORT            = 2170  #porta de origem
DPORT            = 5170  #porta de destino

PRO_TRA          = 0x11 #protocolo de transporte udp

VIDEO_PORT       = 8554 #porta do video

global id
id = 1

linhaContador    = 0;

EXECUTA          = -1
EXECUTA_STREAMING_VIDEO_CONSUMO = 1
EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES = 2

listaStreaming = list()

def primitiveListening(pkt):

  global id

  data_atual = datetime.now()
  data_atual -= timedelta(seconds=OFFSET)

  #resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
  #stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in resp[:12]]).strip()

  resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()

  #print("hash: ", stringPacoteId)
  #exit(1)
  #sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)    
  atualizaListaStreaming(pkt, data_atual, stringPacoteId)
  print("Recebimento: Pacote " + str(id), flush=True)
  id+=1

def atualizaListaStreaming(pktP, dataAtualP, stringPacoteIdP) :

  global listaStreaming
  global linhaContador

  #linhaContador+=1;    
  #listaStreaming.append([str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktP)), ";", "\n"])

  linhaContador+=1;

  #pktP.show()

  cabecalhosC = str(pktP[Ether].dst)+\
                str(pktP[Ether].src)+\
                str(pktP[Ether].type)+\
	        str(pktP[IP].tos)+\
	        str(pktP[IP].id)+\
	        str(pktP[IP].flags)+\
	        str(pktP[IP].frag)+\
	        str(pktP[IP].dst)+\
		str(pktP[IP].src)+\
		str(pktP[IP].proto)+\
		str(pktP[UDP].sport)+\
		str(pktP[UDP].dport);

  hashCabecalhoC = hashlib.sha256(cabecalhosC.encode('utf8')).digest()[:12]
  stringPacoteCabecalhoId = ''.join( [ "%02x" % ord( x ) for x in str(hashCabecalhoC[:12])]).strip()                    
    
  listaStreaming.append(["ENVIOS;", #descricao de envio
                         str(linhaContador)+";", #linhaContador
                         stringPacoteIdP + ";",  #identificador do pacote (hash do conteudo do pacote, que e unico por pacote)
                         str(dataAtualP) + ";" , #data atual em datetime e string do envio do pacote
		         str(datetime.timestamp(dataAtualP)) + ";", #data atual em timestamp e string do envio do pacote
		         stringPacoteCabecalhoId + ";", #dados do cabeçalho para verificacao posterior de taxa de erro
                         str(len(pktP)) + ";", #tamanho do pacote
		         "\n"])

  #file = open("RecebimentoPacotesIPAssincronoServerVideo.csv","w")   
  #for elementosLista in listaStreaming :
  #  file.writelines(elementosLista)      
  #file.close()

  file = open("RecebimentoPacotesIPAssincronoClientVideo.csv","a")
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
  #global id  
  #print("passou aqui ", id)
  #id+=1
  
  #pkt[Ether].dst = MAC_DST
  #sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)
  primitiveListening(pkt)

def gravaStreamingArquivo() :
  file = open("RecebimentoPacotesIPAssincronoServerVideo.csv","w")   
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

  global CONTADOR
  global CONTADOR_ESCUTA
  global OFFSET
  OFFSET = -1

  print("\n********INICIO DADOS DO PROGRAMA")
  print ("")
  print("  Nome do programa........................: " + sys.argv[0])

  if(len(sys.argv) == 1) :
    print ("  Primeiro parametro (execucao).........: Streaming de video para testes - Cliente")
    print ("  Contador: Sem contador")
    EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO
  else :
    print ("  Primeiro parametro (execucao).........: Streaming de video para testes - Cliente")
    print ("  Contador: ", sys.argv[1])
    CONTADOR_ESCUTA = int(sys.argv[1])
    EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES

  print("  sniffing ", IFACE_P_ESCUTA)
  print ("\n********FIM DOS DADOS DO PROGRAMA")

  print("")
  print ("\n********INICIO DA EXECUCAO")
  print("")

  sys.stdout.flush() 

  #inicio modificacao
  resultPS = os.popen('ps', 'r', 256).read()
  bashPID = analisaResultadoPS(resultPS, "bash")

  arquivo  = open('/root/fixp/NTPClient/offsetNTPDate'+str(bashPID)+'.drift', 'r')
  OFFSET   = float(arquivo.readline())
  arquivo.close
  #fim modificacao

  filtro = 'ether proto ' + str(ARQUITETURA_IPV4) + ' and port ' + str(VIDEO_PORT) + ' and host ' + IP_DST + ' or ' + IP_SRC + \
                ' and ip proto ' + str(PRO_TRA)

  if EXECUTA == EXECUTA_STREAMING_VIDEO_CONSUMO :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x))
  elif EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :
    sniff(iface=IFACE_P_ESCUTA, filter=filtro, prn = lambda x: handle_pkt(x), count = CONTADOR_ESCUTA)    
    #gravaStreamingArquivo();
  else :
    print("**************") 
    print("  FIM DE PROGRAMA - ERRO DE EXECUCAO!!!")
    print("**************")   

if __name__ == '__main__':
  main()
