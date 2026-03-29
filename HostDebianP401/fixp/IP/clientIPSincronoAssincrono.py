#!/usr/bin/env python

#SIMULACAO DO CLIENT

#modificacao inicio
#clientIPSincronoAssincrono 1 1000 1500-> envia 1000 pacotes de 1500 bytes da payload cada (FORMA SINCRONA)
#clientIPSincronoAssincrono 2 1000 1500 -> envia 100 pacotes de 1500 bytes da payload cada (FORMA ASSINCRONA, RAJADAS, ENVIO)
#clientIPSincronoAssincrono 3 1000 1500 -> envia 100 pacotes de 1500 bytes da payload cada (FORMA ASSINCRONA, RAJADAS, RECEBIMENTO)
#modificacao fim

import sys
import struct
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from datetime import datetime, timedelta#, timezone, 

import random
import hashlib

ARQUITETURA_IPV4 = 0x0800 

IFACE_P          = 'eth0'

IFACE_P_ESCUTA   = 'eth1'
IFACE_P_ENVIO    = 'eth0'


contador         = 1

IP_DST           =  '192.168.184.102' #IP DO HOST 02
IP_SRC           =  '192.168.171.104' #IP DO HOST 01
		   
MAC_DST          = '08:00:27:a2:64:af'  #MAC DO HOST 02
MAC_SRC          = '08:00:27:47:2b:1d'  #MAC DO HOST 01 			
		    	
SPORT            = 2170  #porta de origem
DPORT            = 5170  #porta de destino

UDP_DPORT_VIDEO  = 8554 #porta do video ffmpegEth

PRO_TRA          = 0x11 #protocolo de transporte 17 -> UDP

dadoEnvido       = '';

EXECUTA          = -1
EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA = 1
EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_ENVIO = 2
EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_RECEBIMENTO = 3

CONTADOR_ESCUTA_ENVIO = -1

listaEnvio = list()
listaRecebimento = list()

linhaContador = 0
linhaContadorRecebimento = 0

frase = ""

TAMANHO_PACOTES = -1

OFFSET = -1

global contadorPacotesRecebidos
contadorPacotesRecebidos = 0

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

  global contador
  global TAMANHO_PACOTES
  global CONTADOR_ESCUTA_ENVIO

  #if Ether in pkt:

   # if pkt[Ether].type == ARQUITETURA_IPV4:
      
    #  if pkt[IP].dst == IP_SRC and pkt[IP].proto == PRO_TRA and pkt[UDP].dport != UDP_DPORT_VIDEO:

     #   conteudo = geraConteudo(TAMANHO_PACOTES)  
  	#primitiveSend(EXECUTA, conteudo)	

  if pkt[UDP].dport != UDP_DPORT_VIDEO:
    atualizaListaRecebimento(pkt)
    
    if(int(EXECUTA) == int(EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA)) : 
      conteudo = geraConteudo(TAMANHO_PACOTES)
      primitiveSend(conteudo)	    

def atualizaListaRecebimento(pktRecebimentoP) :

  global listaRecebimento
  global linhaContadorRecebimento
  global OFFSET
  global contadorPacotesRecebidos

  #modificacao inicio
  data_atual = datetime.now() - timedelta(seconds=OFFSET)
  #modificacao fim
  linhaContadorRecebimento+=1;
  resp = hashlib.sha256(pktRecebimentoP[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()
  
    
  #listaRecebimento.append(["RECEBIMENTOC;", str(linhaContadorRecebimento), ";", stringPacoteId, ";", str(data_atual), ";", str(len(pktRecebimentoP)), ";", "\n"])

  cabecalhosC = str(pktRecebimentoP[Ether].dst)+\
                str(pktRecebimentoP[Ether].src)+\
                str(pktRecebimentoP[Ether].type)+\
	        str(pktRecebimentoP[IP].dst)+\
		str(pktRecebimentoP[IP].src)+\
		str(pktRecebimentoP[IP].proto)+\
		str(pktRecebimentoP[UDP].sport)+\
		str(pktRecebimentoP[UDP].dport);

  hashCabecalhoC = hashlib.sha256(cabecalhosC.encode('utf8')).digest()[:12]
  stringPacoteCabecalhoId = ''.join( [ "%02x" % ord( x ) for x in str(hashCabecalhoC[:12])]).strip()      


  listaRecebimento.append(["RECEBIMENTOC;", #descricao de envio
                          str(linhaContadorRecebimento)+";", #linhaContador
                          stringPacoteId + ";",  #identificador do pacote (hash do conteudo do pacote, que e unico por pacote)
                          str(data_atual) + ";" , #data atual em datetime e string do envio do pacote
		          str(datetime.timestamp(data_atual)) + ";", #data atual em timestamp e string do envio do pacote
                          stringPacoteCabecalhoId + ";", #dados do pacote para taxa de erros
                          str(len(pktRecebimentoP)) + ";", #tamanho do pacote
		          "\n"])

  if(int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_RECEBIMENTO)) :
    contadorPacotesRecebidos += 1
    print("Pacote recebido numero: " + str(linhaContadorRecebimento), flush=True)
    file = open("RecebimentoPacotesIPAssincronoCliente.csv","a")
    file.writelines(listaRecebimento[len(listaRecebimento)-1])      
    file.close()


def primitiveSend(conteudoP) :
  
  #print("hash: ", stringPacoteId)
  #exit(1)
  global frase
  global OFFSET
  pkt = Ether(dst=MAC_DST, src=MAC_SRC, type=0x800)

  pkt = pkt / IP(dst=IP_DST, src=IP_SRC, proto=PRO_TRA)

  pkt = pkt / UDP(sport=SPORT, dport=DPORT)

  pkt = pkt / Raw(load = conteudoP)

  resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()

  
  #modificacao inicio
  data_atual = datetime.now() 
  #print("Data atual ", data_atual)
  data_atual -= timedelta(seconds=OFFSET)
  #print("Data atual com offset", data_atual) 
  #modificacao fim

  sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)

  atualizaListaEnvio(pkt, data_atual, stringPacoteId)

  print(frase, flush=True)


def atualizaListaEnvio(pktEnvioP, dataAtualP, stringPacoteIdP) :

  global listaEnvio
  global linhaContador

  linhaContador+=1;

  cabecalhosC = str(pktEnvioP[Ether].dst)+\
                str(pktEnvioP[Ether].src)+\
                str(pktEnvioP[Ether].type)+\
	        str(pktEnvioP[IP].dst)+\
		str(pktEnvioP[IP].src)+\
		str(pktEnvioP[IP].proto)+\
		str(pktEnvioP[UDP].sport)+\
		str(pktEnvioP[UDP].dport);
 
  hashCabecalhoC = hashlib.sha256(cabecalhosC.encode('utf8')).digest()[:12]
  stringPacoteCabecalhoId = ''.join( [ "%02x" % ord( x ) for x in str(hashCabecalhoC[:12])]).strip()                    
    
  listaEnvio.append(["ENVIOC;", #descricao de envio
                     str(linhaContador)+";", #linhaContador
                     stringPacoteIdP + ";",  #identificador do pacote (hash do conteudo do pacote, que e unico por pacote)
                     str(dataAtualP) + ";" , #data atual em datetime e string do envio do pacote
		     str(datetime.timestamp(dataAtualP)) + ";", #data atual em timestamp e string do envio do pacote
		     stringPacoteCabecalhoId + ";", #dados do cabeçalho para verificacao posterior de taxa de erro
                     str(len(pktEnvioP)) + ";", #tamanho do pacote
		     "\n"])

def gravaStreamingArquivoEnvio(nomeArquivo) :
  file = open(nomeArquivo,"w")
   
  for elementosLista in listaEnvio :
    file.writelines(elementosLista)      

  file.close()

def gravaStreamingArquivoRecebimento(nomeArquivo) :
  file = open(nomeArquivo,"w")
   
  for elementosLista in listaRecebimento :
    file.writelines(elementosLista)      

  file.close()

def geraConteudo(tamanhoConteudo) :

  global contador
  global frase

  conteudo = 'Referente a solicitacao numero ' + str(contador) + "."  
  #so para movimentar algo na tela
  frase = "Envio de solicitacao " + str(contador)
  contador += 1  

  listaSimbolos = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q',
                   'r','s','t','u','v','w','x','y','z','*','!','@','#','%','&','(',')',
                   '|',',','.',':',',','<','>','?','/','_','-','+','=','"']

  escolhasSimbolos = ''.join(random.choice(listaSimbolos))

  conteudo += escolhasSimbolos 

  for i in range(int(tamanhoConteudo) - len(conteudo)) :
    conteudo += ''.join(random.choice(listaSimbolos))
     	
  return conteudo

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
  global CONTADOR_ESCUTA_ENVIO
  global contador
  global TAMANHO_PACOTES
  global OFFSET

  print ("\n********INICIO DADOS DO PROGRAMA")
  print ("")
  print ("  Nome do programa........................: " + sys.argv[0])

  #print(len(sys.argv))

  if(len(sys.argv) == 4) :

    EXECUTA = sys.argv[1]
    CONTADOR_ESCUTA_ENVIO = sys.argv[2]
    TAMANHO_PACOTES = sys.argv[3]

    #print("EXECUTA: %d" %(int(EXECUTA)))
    
    if(int(EXECUTA) == int(EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA)) :
      print ("  Primeiro parametro (execucao).........: Envio de mensagens forma sincrona - Client")
    elif (int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_ENVIO)) :
      print ("  Primeiro parametro (execucao)...........: Envio de mensagens forma assincrona - Envio Client")
    elif (int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_RECEBIMENTO)) :
      print ("  Primeiro parametro (execucao)...........: Envio de mensagens forma assincrona - Recebimento Client")
    else :
      print("  Parametros invalidos")
      exit(1)

  else :

    print("  Erro! Parametros invalidos")
    exit(1)

  print("  sniffing ", IFACE_P)
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

  if(int(EXECUTA) == int(EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA)) : 
    conteudo = geraConteudo(TAMANHO_PACOTES)    
    primitiveSend(conteudo)
    filtro = '''ether proto ''' + str(ARQUITETURA_IPV4) + ''' and ip dst ''' + IP_SRC + ''' and
                ip proto ''' + str(PRO_TRA) + ' and port !8554 ' 
    sniff(iface=IFACE_P, filter = filtro, prn = lambda x: handle_pkt(x), count = int(CONTADOR_ESCUTA_ENVIO))  
    gravaStreamingArquivoEnvio("EnvioPacotesIPSincronoCliente.csv")
    gravaStreamingArquivoRecebimento("RecebimentoPacotesIPSincronoCliente.csv")
  elif (int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_ENVIO)) :
    for i in range(int(CONTADOR_ESCUTA_ENVIO)) :
      conteudo = geraConteudo(TAMANHO_PACOTES)        
      primitiveSend(conteudo)
    gravaStreamingArquivoEnvio("EnvioPacotesIPAssincronoCliente.csv")
  elif(int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO_RECEBIMENTO)) : 
    #conteudo = geraConteudo(TAMANHO_PACOTES)    
    #primitiveSend(conteudo)
    filtro = '''ether proto ''' + str(ARQUITETURA_IPV4) + ''' and ip dst ''' + IP_SRC + ''' and
	        ip proto ''' + str(PRO_TRA) + ' and port !8554 ' 
    sniff(iface=IFACE_P, filter = filtro, prn = lambda x: handle_pkt(x), count = int(CONTADOR_ESCUTA_ENVIO))  
    #gravaStreamingArquivoEnvio("EnvioPacotesIPSincronoCliente.csv")
    #gravaStreamingArquivoRecebimento("RecebimentoPacotesIPAssincronoCliente.csv")


    
if __name__ == '__main__':
  main()
