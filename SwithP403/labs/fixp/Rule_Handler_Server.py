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

#CONSTANTES DO SWITCH P4
ARQUITETURA_IPV4           = 0x0800 
ARQUITETURA_ETARCH         = 0x0880 
ARQUITETURA_FIXP           = 0x0900 
ARQUITETURA_NG             = 0x1234   
I_FACE                     = 'eth0'
TABLE_ADD_COMMAND          = 1
TABLE_DELETE_WKEY_COMMAND  = 2
MC_MGRP_CREATE             = 3
MC_MGRP_DESTROY            = 4

ACERTO_OPERACAO               = 0
ERRO_LISTA_ACOES              = 1
ERRO_ID_ARQUITETURA           = 2
ERRO_EXECUCAO_COMANDO         = 3
ERRO_FAIXA_IDENTIFICADOR_DROP = 4
ERRO_FAIXA_COMANDO            = 5
ERRO_THRIFT_PORT              = 6
ERRO_LISTA_CHAVES             = 7

#TODO: define data received

def arquiteturaRequisitora(arquitetura) :

  if(hex(arquitetura) == 0x800) :
 
    return 'IPv4'

  elif (hex(arquitetura) == 0x880) :

    return 'ETArch'

  elif (hex(arquitetura) == 0x1234) :
 
    return 'Nova Genesis'

  else :

    return '-1'

def retornaAcoesParametrosString(arquiteturaP, idPacoteP, listaAcoesP, listaParametrosAcoesP) :

  stringRetornada = ""
  i = 0

  if(len(listaAcoesP) != len(listaParametrosAcoesP)):

    for listaAcoes in listaAcoesP :

      stringRetornada += listaAcoes
     
      listaParametrosAcoesParcial = listaParametrosAcoesP[i]

      ItensCorrentesListaParametros = " ".join(listaParametrosAcoesParcial)	

      stringRetornada += ItensCorrentesListaParametros 

      i += 1 

    return(stringRetornada)

  else :

    print("Erro! Inconsistencia de informacoes quanto a lista de acoes recebidas da arquitetura %s, packetId %d" 
           %(arquiteturaRequisitora(arquiteturaP), idPacoteP))

    return("-1")

def montaComandoTDW(nomeTabelaP, listaChavesP) :
  return("table_delete_wkey " + nomeTabelaP + " " + listaChavesP)

def montaComandoAD(thriftPort) :
  deviceId   = -1
  p4ConfigId = -1
  
  if(thriftPort==9090) :
    deviceId = 0
    p4ConfigId = 0
    return("assign_device " + str(deviceId) + " " + str(p4ConfigId))  
  
  print("Erro no envio da thrift-port")
  return("-1") 	

def montaComandoTA(nomeTabelaP, listaChavesPS, listaAcoesParametrosSP) :
  return("table_add " + nomeTabelaP + " " + listaChavesPS + " " + listaAcoesParametrosSP)

def runCommandP4(rawData) :

  commandsList = list()

  if len(rawData) == 0 :
    print("Erro! Inconsistencia dos dados recebidos.")
    return(-1)

  if p4Command == TABLE_ADD_COMMAND :

    tableDeletekeyCommandS = ""
    tableAddCommandS = ""

    for rawDataLine in rawData :	

      (arquitecture,
       geradorPacketId, 
       switch, 
       thriftPort, 
       p4Command,
       tableName,
       KeysList,
       actionsList,
       parametersList,
       dropIdentificator) = (rawDataLine[0], #arquitecture
	    		     rawDataLine[1], #geradorPacketId
	  	    	     rawDataLine[2], #switch
  	    		     rawDataLine[3], #thrift-port  
	    		     rawDataLine[4], #p4Command
	    		     rawDataLine[5], #nome completo da tabela
	    		     rawDataLine[6], #lista de chaves
	    		     rawDataLine[7], #lista de acoes
	    		     rawDataLine[8], #lista de parametros das acoes
	    		     rawDataLine[9]) #identificador de drop

      if len(rawDataLine[6]) == 0 :
        print("Erro! Envio de chaves invalida")
	return(ERRO_LISTA_CHAVES)

      keysListString = " ".join(rawDataLine[6])
            	 	
      ActionsListString = retornaAcoesParametrosString(rawDataLine[0], rawDataLine[1], rawDataLine[7], rawDataLine[8])
      if ActionListString == "-1" :
	return(ERRO_LISTA_ACOES)

      comandoAD = montaComandoAD(rawDataLine[3])
      if comandoAD == "-1" :
        return(ERRO_THRIFT_PORT)
         	  	      
      commandsList.append(comandoAD)	
      	 		
      if (dropIdentificator in [0,1]) :

        if (dropIdentificator == 1) :
	            
          commandsList.append(montaComandoTDW(rawDataLine[5], keysListString))
          	            
      else :

        print('Erro! Identificador de Drop esta fora da faixa.')
        return(ERRO_FAIXA_IDENTIFICADOR_DROP)

      commandsList.append(montaComandoTA(rawDataLine[0], rawDataLine[5], keysListString, ActionsListString))

      for rowCommands in commandsList :

        print(rowCommands)

      print("FIM")
	      	    
  else :

    print("ERRO! Comando P4 ainda nao configurado.")
    return(ERRO_FAIXA_COMANDO)

  			  			  			   
def handle_pkt(pkt):

  if Ether in pkt:

    if pkt[Ether].type == ARQUITETURA_FIXP and pkt[Ether].dst == '46:49:58:50:00:00' : #FIXP (CONTROLLER TO SWITCH)
     
      print("Requisicao de encaminhento")

      rawData = json.loads(pkt[Raw].load)

      status = runCommandP4(rawData)	
          
      ifaceChoice = choiceIface(ARQUITETURA_FIXP, switch)

      pkt.show2()	   		
	
      sendp(pkt, iface=ifaceChoice, verbose=False)

		          
def main():

  print "sniffing " + I_FACE

  sys.stdout.flush()

  sniff(iface=I_FACE, prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
  main()
