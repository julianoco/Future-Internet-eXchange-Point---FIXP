#!/usr/bin/env python

#SIMULACAO DO CLIENT

#clientEtarchSincronoAssincrono 1 1000 1500 w1-> envia 1000 pacotes de 1500 bytes da payload cada (FORMA SINCRONA) no worskpace w1
#clientEtarchSincronoAssincrono 2 1000 1500 w1 -> envia 100 pacotes de 1500 bytes da payload cada (FORMA ASSINCRONA, RAJADAS) no workspace w1

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

ARQUITETURA_ETARCH = 0x0880 

IFACE_P_ESCUTA   = 'eth0'
IFACE_P_ENVIO    = 'eth0'

contador         = 1

MAC_DST          = ''  #WORKSPACE
MAC_SRC          = ''  #NAO FAZ DIFERENCA O MAC DE ORIGEM 			
		    	
EXECUTA          = -1
EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA = 1
EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO = 2

CONTADOR_ESCUTA_ENVIO = -1

CHAVE_WORKSPACE = '-1'

listaEnvio = list()
listaRecebimento = list()

linhaContador = 0
linhaContadorRecebimento = 0

frase = ""

TAMANHO_PACOTES = -1



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

  #if pkt[UDP].dport != UDP_DPORT_VIDEO:
  atualizaListaRecebimento(pkt)
  conteudo = geraConteudo(TAMANHO_PACOTES)
  primitiveSend(conteudo)	    

def atualizaListaRecebimento(pktRecebimentoP) :

  global listaRecebimento
  global linhaContadorRecebimento

  data_atual = datetime.now()
  linhaContadorRecebimento+=1;
  resp = hashlib.sha256(pktRecebimentoP[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()
  
    
  listaRecebimento.append(["RECEBIMENTOC;", str(linhaContadorRecebimento), ";", stringPacoteId, ";", str(data_atual), ";", str(len(pktRecebimentoP)), ";", "\n"])

def primitiveSend(conteudoP) :
  global CHAVE_WORKSPACE
  #print("hash: ", stringPacoteId)
  #exit(1)
  global frase
  pkt = Ether(dst=CHAVE_WORKSPACE, src=MAC_SRC, type=ARQUITETURA_ETARCH)

  #pkt = pkt / IP(dst=IP_DST, src=IP_SRC, proto=PRO_TRA)
  #pkt = pkt / UDP(sport=SPORT, dport=DPORT)

  pkt = pkt / Raw(load = conteudoP)

  #pkt[0].show()

  resp = hashlib.sha256(pkt[Raw].load).digest()[:12]
  stringPacoteId = ''.join( [ "%02x" % ord( x ) for x in str(resp[:12])]).strip()

  data_atual = datetime.now()
  sendp(pkt, iface=IFACE_P_ENVIO, verbose=False)

  atualizaListaEnvio(pkt, data_atual, stringPacoteId)

  print(frase)


def atualizaListaEnvio(pktEnvioP, dataAtualP, stringPacoteIdP) :

  global listaEnvio
  global linhaContador

  linhaContador+=1;
    
  listaEnvio.append(["ENVIOC;", str(linhaContador), ";", stringPacoteIdP, ";", str(dataAtualP), ";", str(len(pktEnvioP)), ";", "\n"])

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

  conteudo = 'Referente a solicitacao numero ' + str(contador)  
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
  
def main():

  global EXECUTA
  global CONTADOR_ESCUTA_ENVIO
  global contador
  global TAMANHO_PACOTES
  global MAC_DST
  global MAC_SRC
  global CHAVE_WORKSPACE

  print ("\n********INICIO DADOS DO PROGRAMA")
  print ("")
  print ("  Nome do programa........................: " + sys.argv[0])
    
  #print(len(sys.argv))

  if(len(sys.argv) == 5) :

    MAC_SRC = get_if_hwaddr(IFACE_P_ENVIO)

    EXECUTA = sys.argv[1]
    CONTADOR_ESCUTA_ENVIO = sys.argv[2]
    TAMANHO_PACOTES = sys.argv[3]
    CHAVE_WORKSPACE = ":".join("{:02x}".format(ord(c)) for c in hashlib.sha256(sys.argv[4]).digest()[:6])

    print("EXECUTA: %d" %(int(EXECUTA)))
    
    if(int(EXECUTA) == int(EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA)) :
      print ("  Primeiro parametro (execucao).........: Envio de mensagens forma sincrona - Client")
    elif (int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO)) :
      print ("  Primeiro parametro (execucao)...........: Envio de mensagens forma assincrona - Client")
    else :
      print("  Parametros invalidos")
      exit(1)

  else :

    print("  Erro! Parametros invalidos")
    exit(1)

  print("  sniffing ", IFACE_P_ESCUTA)
  print("\n********FIM DOS DADOS DO PROGRAMA")

  print("")
  print("\n********INICIO DA EXECUCAO")
  print("")

  sys.stdout.flush() 

  if(int(EXECUTA) == int(EXECUTA_CHAT_ENVIO_INFORMACOES_SINCRONA)) : 
    conteudo = geraConteudo(TAMANHO_PACOTES)    
    primitiveSend(conteudo)
    filtro = '''ether proto ''' + str(ARQUITETURA_ETARCH) #+ ''' and ip dst ''' + IP_SRC + ''' and
	        #ip proto ''' + str(PRO_TRA)
    sniff(iface=IFACE_P_ESCUTA, filter = filtro, prn = lambda x: handle_pkt(x), count = int(CONTADOR_ESCUTA_ENVIO))  
    gravaStreamingArquivoEnvio("EnvioPacotesEtarchSincronoCliente.csv")
    gravaStreamingArquivoRecebimento("RecebimentoPacotesEtarchSincronoCliente.csv")
  elif (int(EXECUTA) == int(EXECUTA_CHAT_RAJADA_INFORMACOES_ASSINCRONO)) :
    for i in range(int(CONTADOR_ESCUTA_ENVIO)) :
      conteudo = geraConteudo(TAMANHO_PACOTES)        
      primitiveSend(conteudo)
    gravaStreamingArquivoEnvio("EnvioPacotesEtarchAssincronoCliente.csv")
    
if __name__ == '__main__':
  main()
