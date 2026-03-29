#envia video para cliente / host 06

#host02 oficial

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

linhaContador    = 0;

EXECUTA          = -1
EXECUTA_STREAMING_VIDEO_CONSUMO = 1
EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES = 2

#CHAVE_WORKSPACE = '-1'
#NAO DA PARA GERAR A CHAVE DA MESMA FORMA DO PYTHON2, A FUNCAO HASHLIB E DIGEST MODIFICARAM
#E ISS PROVOCA UMA MODIFICACAO NO RESULTADO
#POR CONTA DISSO COLOCAMOS UMA CONSTANTE PARA FINS DE EXPERIMENTO
#A CHAVE ABAIXO REPRESENTA O WORKSPACE w1
#global CHAVE_WORKSPACE
#CHAVE_WORKSPACE = '60:c5:59:0f:72:ee'

global id
id=1


listaStreaming = list()

def primitiveListening(pkt, dataAtualP):
  #data_atual = datetime.now()
  #[28:] pula 28 bytes (20 bytes do IP e 8 bytes do UDP) 
  #print("Raw..: ", pkt[Raw].load[28:])
  #print("Lng..: ", len(pkt[Raw].load[28:]))

  #resp = hashlib.sha256(pkt[Raw].load[28:]).digest()[:12]
  #stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in resp[:12]]).strip()
  resp = hashlib.sha256(pkt[Raw].load[28:]).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()


  #print("hash: ", stringPacoteId)
  #exit(1)
  #sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)    
  atualizaListaStreaming(pkt, dataAtualP, stringPacoteId)

def atualizaListaStreaming(pktP, dataAtualP, stringPacoteIdP) :

  global listaStreaming
  global linhaContador

  #linhaContador+=1;    
  #listaStreaming.append([str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktP)), ";", "\n"])

#--------------codigo repetido e necessario para pegar o codigo do cabecalho da origem

  #REPRODUCAO DO QUE FOI ENVIADO PELO SERVIDOR

  pkt_envio = Ether(dst=pktP[Ether].dst, src=pktP[Ether].src, type=ARQUITETURA_ETARCH) #/ pkt

  #monta cabecalho IP que esta encapsulado (de 20 bytes)
  pkt_envio_temp = IP(pktP[Raw].load[0:20])
  pkt_envio_temp = pkt_envio_temp / UDP(pktP[Raw].load[20:28])
  pkt_envio_temp = pkt_envio_temp / Raw(pktP[Raw].load[28:])

  pkt_envio = pkt_envio / IP(tos   = pkt_envio_temp[IP].tos,
			     id    = pkt_envio_temp[IP].id,
			     flags = pkt_envio_temp[IP].flags,
			     frag  = pkt_envio_temp[IP].frag,
			     ttl   = pkt_envio_temp[IP].ttl,
			     proto = pkt_envio_temp[IP].proto,
			     dst   = pkt_envio_temp[IP].dst,
			     src   = pkt_envio_temp[IP].src )  

  pkt_envio = pkt_envio / UDP(sport=pkt_envio_temp[UDP].sport, dport=pkt_envio_temp[UDP].dport)
  pkt_envio = pkt_envio / Raw(load = pkt_envio_temp[Raw].load)

  linhaContador+=1;

  cabecalhosC = str(pkt_envio[Ether].dst)+\
                str(pkt_envio[Ether].src)+\
                str(pkt_envio[Ether].type)+\
	        str(pkt_envio[IP].tos)+\
	        str(pkt_envio[IP].id)+\
	        str(pkt_envio[IP].flags)+\
	        str(pkt_envio[IP].frag)+\
	        str(pkt_envio[IP].dst)+\
		str(pkt_envio[IP].src)+\
		str(pkt_envio[IP].proto)+\
		str(pkt_envio[UDP].sport)+\
		str(pkt_envio[UDP].dport);

  hashCabecalhoC = hashlib.sha256(cabecalhosC.encode('utf8')).digest()[:12]
  stringPacoteCabecalhoId = ''.join( [ "%02x" % ord( x ) for x in str(hashCabecalhoC[:12])]).strip()                    
    
  listaStreaming.append(["RECEBIMENTOC;", #descricao de envio
                         str(linhaContador)+";", #linhaContador
                         stringPacoteIdP + ";",  #identificador do pacote (hash do conteudo do pacote, que e unico por pacote)
                         str(dataAtualP) + ";" , #data atual em datetime e string do envio do pacote
		         str(datetime.timestamp(dataAtualP)) + ";", #data atual em timestamp e string do envio do pacote
		         stringPacoteCabecalhoId + ";", #dados do cabeçalho para verificacao posterior de taxa de erro
                         str(len(pktP)) + ";", #tamanho do pacote
		         "\n"])

  file = open("RecebimentoPacotesEtarchAssincronoServerVideo02.csv","a")
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

def primitiveSend(pkt):

  global MAC_SRC
  global IP_SRC
  global CHAVE_WORKSPACE
  global id

  #pkt_envio = Ether(dst=MAC_SRC, src=pkt[Ether].src, type=ARQUITETURA_IPV4) #/ pkt
  #para executar de dentro do host, ou seja, o proprio hosto mandando para host, duas coisas e necessaria para que o ffmplay abra
  #primeiro. o mac tem que ir zerado, o ip pouco importa
  #segundo. o envio tem que ocorrer para a inteface de loopback, ela tem a responsabilidade de mandar pacote para dentro do host para host
  #quando o host e o propra maquina, ou seja, maquina mandando mensagem para propria maquina
  #tudo ocorreu bem, abaixo fazemos o desencapsulamento das informacoes.
  pkt_envio = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=ARQUITETURA_IPV4) #/ pkt

  #monta cabecalho IP que esta encapsulado (de 20 bytes)
  pkt_envio_temp = IP(pkt[Raw].load[0:20])
  pkt_envio_temp = pkt_envio_temp / UDP(pkt[Raw].load[20:28])
  pkt_envio_temp = pkt_envio_temp / Raw(pkt[Raw].load[28:])

  #DST = IP_SRC. ISSO FOI FEITO PARA O ENVIO DEVIDO A CENARIOS COM MAIS DE 1 ENTIDADE, ONDE O DESTINO E A PROPRIA ENTIDADE
  pkt_envio = pkt_envio / IP(tos   = pkt_envio_temp[IP].tos,
			     id    = pkt_envio_temp[IP].id,
			     flags = pkt_envio_temp[IP].flags,
			     frag  = pkt_envio_temp[IP].frag,
			     ttl   = pkt_envio_temp[IP].ttl,
			     proto = pkt_envio_temp[IP].proto,
			     dst   = IP_SRC, #EXPLICACAO ESTA ACIMA
			     src   = pkt_envio_temp[IP].src )  

  pkt_envio = pkt_envio / UDP(sport=pkt_envio_temp[UDP].sport, dport=pkt_envio_temp[UDP].dport)
  pkt_envio = pkt_envio / Raw(load = pkt_envio_temp[Raw].load)

  #data_atual = datetime.now()
  #sendp(pkt_envio, iface=IFACE_P_ENVIO, verbose=False)
  sendp(pkt_envio, iface="lo", verbose=False)

  #if EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES :      
  #  atualizaListaStreaming(pkt_envio, data_atual, stringPacoteId) 

  print("Envio: Pacote " + str(id), flush=True)  
  id+=1


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
  #print("Requisicao de video ", id)
  #id+=1
  
  #pkt[Ether].dst = MAC_DST
  #sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)
  #print("teste", flush=True)
  dataAtual = datetime.now()
  dataAtual -= timedelta(seconds=OFFSET)

  #if(EXECUTA == EXECUTA_STREAMING_VIDEO_CONSUMO) :
  primitiveSend(pkt)    
  
  if (EXECUTA == EXECUTA_STREAMING_VIDEO_TESTES) : 
    primitiveListening(pkt, dataAtual)

def gravaStreamingArquivo() :
  file = open("recebimentoPacotesMetricaVideo.csv","w")
   
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
  global CONTADOR_ESCUTA
  global MAC_SRC
  global IP_SRC
  global CHAVE_WORKSPACE
  global OFFSET
  OFFSET = -1

  print ("\n********INICIO DADOS DO PROGRAMA")
  print ("")
  print("  Nome do programa........................: " + sys.argv[0]) 

  if(len(sys.argv) == 1) :
    print ("  Primeiro parametro (execucao).........: Streaming de video para consumo - Cliente")
    print ("  Contador: Sem contador")
    EXECUTA = EXECUTA_STREAMING_VIDEO_CONSUMO
  else :
    print ("  Primeiro parametro (execucao).........: Streaming de video para testes - Cliente")
    print ("  Contador: ", sys.argv[1])
    CONTADOR_ESCUTA = int(sys.argv[1])
    EXECUTA = EXECUTA_STREAMING_VIDEO_TESTES

  print("  sniffing ", IFACE_P_ESCUTA)
  print("\n********FIM DOS DADOS DO PROGRAMA")

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


  IP_SRC  = get_if_addr  (IFACE_P_ENVIO)
  MAC_SRC = get_if_hwaddr(IFACE_P_ENVIO)

  filtro = 'ether proto ' + str(ARQUITETURA_ETARCH)

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
