#!/usr/bin/env python

#desligou switch, tem que desligar o controlador e vice-versa, pois as estruturas de armazenamento estao em 
#estrutura de dados e nao em banco de dados

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
ARQUITETURA_IPV4           = "0x0800" 
ARQUITETURA_ETARCH         = "0x0880"
ARQUITETURA_FIXP           =  0x0900
ARQUITETURA_NG             = "0x1234"  
ARQUITETURA_NG_SIMULACAO   = "0x1235"   
ARQUITETURA_FIXP_S_H       =  "0x0900"
I_FACE                     = 'eth3'
TABLE_ADD_COMMAND          = 1
MC_ADD_COMMAND             = 2

#TABLE_DELETE_WKEY_COMMAND  = 2
#MC_MGRP_CREATE             = 3
#MC_MGRP_DESTROY            = 4

STATUS_SUCESSO                       = 0
STATUS_FALHA			     = 1
ERRO_LISTA_ACOES                     = 1
ERRO_ID_ARQUITETURA                  = 2
ERRO_EXECUCAO_COMANDO                = 3
ERRO_FAIXA_IDENTIFICADOR_DROP        = 4
ERRO_FAIXA_COMANDO                   = 5
ERRO_THRIFT_PORT                     = 6
ERRO_LISTA_CHAVES                    = 7
ERRO_SWITCH_PORT                     = 8
ERRO_INCONSISTENCIA_DADOS            = 9
ERRO_LISTA_PORTAS                    = 10
ERRO_ATUALIZACAO_HANDLES             = 11
ERRO_PARAMETROS_COMANDOS_DEPENDENTES = 12
ERRO_VALIDACAO_GRUPO		     = 13

SWITCH_CORRENTE               = 's01'
THRIFT_PORT                   = 9090

CAMINHO_PI_CLI_BMV2           = "/home/student/PI/CLI/"
CAMINHO_JSON_FILE             = "/home/student/labs/fixp/p4prog/"
CAMINHO_SWT_AT                = "./"
NOME_ARQUIVO_JSON             = "fixp.json"

CAMINHO_SSWITCH_CLI           = "/home/student/bmv2/targets/simple_switch/"

geradorRid                    = 3   #dados compartilhados entre controladores 
geradorGrupo                  = 2   #dados compartilhados entre controladores

thriftPortList                = [9090]

listaGruposRegistrados        = list()

#TODO: define data received

def arquiteturaRequisitora(arquitetura) :

  if(arquitetura == int(ARQUITETURA_IPV4,16)) :
 
    return 'IPv4'

  elif (arquitetura == int(ARQUITETURA_ETARCH,16)) :

    return 'ETArch'

  elif (arquitetura == int(ARQUITETURA_NG, 16)) :
 
    return 'Nova Genesis'

  elif (arquitetura == int(ARQUITETURA_NG_SIMULACAO, 16)) :
 
    return 'Nova Genesis (SIMULACAO)'

  else :

    return '-1'

def retornaAcoesParametrosString(listaAcoesP, listaParametrosAcoesP, groupIdP) :

  stringRetornada = ""
  i = 0

  print("Lista de acoes: ", listaAcoesP)
  print("Lista de parametros: ", listaParametrosAcoesP)
  print("Comprimentos %d %d" %(len(listaAcoesP), len(listaParametrosAcoesP)))

  if(len(listaAcoesP) == len(listaParametrosAcoesP)):

    for listaAcoes in listaAcoesP :

      listaParametrosAcoesParcial = list()

      stringRetornada += listaAcoes

      #print("String Retornada 1", stringRetornada)
     
      #TEM UM ERRRINHO. QUANDO FOR GRUPO, NAO QUER DIZER QUE O PARAMETRO VAI SE SO DO GRUPO, ENTAO PODEM HAVER OUTROS PARAMETROS
      #POR ISSO TEM QUE SER CONSERTADO
      if(groupIdP == -1) :#passagem de parametros de acao manual pelo controlador 
        listaParametrosAcoesParcial = listaParametrosAcoesP[i]
      else : #houve configuracao automatica de grupos e sao esses parametros que tem que ser passados
        for rowListaParametros in listaParametrosAcoesP[i] : #coloca o grupo que foi configurado nos parametros da acao
	  listaParametrosAcoesParcial.append(groupIdP) #acho que nao funciona direito, se tivesse mais parametros iria colocar groupIdP	
						       #de forma repetida? Para um parametro vai funcionar
      print("Lista de parametros parcial: ", listaParametrosAcoesParcial)

      #ItensCorrentesListaParametros = " ".join(listaParametrosAcoesParcial)	
      for elementos in listaParametrosAcoesParcial :
        stringRetornada += " " + str(elementos)        	

      stringRetornada += " "

      i += 1 

    print("String Retornada 1", stringRetornada)

    return(stringRetornada)

  else :
    #o fixp esta deixando apenas um parametro por acao? se for isso esta errado. uma acao poderia ter mais de 1 parametro
    print("Erro! Inconsistencia de informacoes quanto a lista de acoes recebidas da arquitetura corrente")

    return("-1")

def montaComandoTDW(nomeTabelaP, listaChavesP) :
  return("table_delete_wkey " + nomeTabelaP + " " + listaChavesP)

def montaComandoAD(thriftPort) :
  deviceId   = -1
  p4ConfigId = -1
  
  if(thriftPort in thriftPortList) : #modificadoV4
    deviceId = 0
    p4ConfigId = 0
    
    #cada dispositivo (switch) e controlado por um P4RUNTIME (bibliotecas e programa P4)
    return("assign_device " + str(deviceId) + " " + str(p4ConfigId)) + " -- port = " + str(thriftPort)
  
  print("Erro no envio da thrift-port")
  return("-1") 	

def montaComandoTA(nomeTabelaP, listaChavesPS, listaAcoesParametrosSP) :
  return("table_add " + nomeTabelaP + " " + listaChavesPS + " => " + listaAcoesParametrosSP)

def organizaListaParaExecucao(commandsListP) :

  commandListFile = list()

  for rowCommandsList in commandsListP :
    commandListFile.append(rowCommandsList)
    commandListFile.append("\n")

  del(commandListFile[len(commandListFile)-1])
 
  return(commandListFile)
    
def retornaHandlesList(result, simP = ".") :

  retorno = list()

  resultado = result.lower()

  if(resultado.find("erro") != -1 or resultado.find("invalid") != -1) :   
    return([-1])

  while(resultado.find("handle") != -1) :

    if(resultado.find(simP) > resultado.find("handle")) :

      retorno.append(int(resultado[(resultado.find("handle")+7):resultado.find(simP)]))

    resultado = resultado[(resultado.find(simP)+1):len(resultado)]

  return retorno    

def retornaElementosListaSeparadas(listaP, sepP = " ") :

  stringRetornada = ""
  i = 0

  for elemento in listaP :

      if i == 0 :
        stringRetornada += str(elemento)
      else:
        stringRetornada += sepP + str(elemento)
  
      i += 1

  print("String Retornada ", stringRetornada)

  return(stringRetornada)

def montaComandoMC_ADD_MODIFY(groupIdP, listaGruposP, dropIdentificatorP) :

  #[ [RID, lista de portas, handle_node, handle_associate] ]
  # [[-1, [2], -1, -1]]
  # [[3, [2, 3], 0, -1]]

  global geradorRid
  global geradorGrupo

  listaComandos  = list()
  listaComandosD = list() #comandos dependentes
  listaAtualizacaoHandles = list()

  if groupIdP == -1 :
    groupId = geradorGrupo
    geradorGrupo += 1
  else :
    groupId = groupIdP

  i = 0

  for rowListaGrupos in listaGruposP :
     
    #vai criar apenas um no com varias portas, ou seja, as portas estarao separadas por espaco
    rowListaPortasS = retornaElementosListaSeparadas(rowListaGrupos[1])
    	
    if (dropIdentificatorP in [0,1]) :
      
      if (dropIdentificatorP == 1) :
	#JULIANO ATUAL: ABAIXO O GRUPO_ID E RID (HANDLE_NODE) -> ROWLISTAGRUPOS
	listaComandos.append('mc_node_dissociate ' + str(groupId) + ' ' + str(rowListaGrupos[2]))
        listaComandos.append('mc_node_destroy ' + str(rowListaGrupos[2]))
	if i == 0 : #se tivesse uma lista de handles_associates; handles_nodes; esse teria que ser o ultimo comando executado (errado)			
		    #primeiro teria que trabalhar as desconstrucoes da tabela por inteiro, depois construi-las novamente
		    #parte-se do pressuposto que sempre teremos apenas um handle_node	
		    #a solucao seria criar listas diferentes para esse comando e para o mc_mgrp_create	

          #parece que o destroy destroy tudo, o grupo e suas associacoes, o que faria nao precisar de um loop para fazer varios
          #mc_node_dissociate e mc_node_destroy
	  #nao tem problema, esta fazendo certo, nao precisa de loop, pois na hora de criar o mc_node_create ele cria todas as
	  #portas de uma so vez
          listaComandos.append('mc_mgrp_destroy ' + str(groupId))
                  	            
    else :
      #acho que aqui tem um erro, retorna tupla com apenas dois elementos
      #mas acho que pode, depois tem que ver
      print('Erro! Identificador de Drop esta fora da faixa.')
      return((ERRO_FAIXA_IDENTIFICADOR_DROP, -1))

    if i == 0 : 
      listaComandos.append('mc_mgrp_create ' + str(groupId))
 
    listaComandos.append('mc_node_create ' + str(geradorRid) + " " + rowListaPortasS)	
    #? e porque precisa saber qual sera o handle de mc_node_create	
    listaComandosD.append('mc_node_associate ' + str(groupId) + " ?")    

    rowListaGruposAux    = rowListaGrupos
    rowListaGruposAux[0] = geradorRid    
             
    listaAtualizacaoHandles.append(rowListaGruposAux)
    
    i += 1
    geradorRid += 1    

  return (listaComandos, listaComandosD, listaAtualizacaoHandles, groupId)


def substituiParametrosCD(commandsListD, listaHandlesRetornadosP) :
  
  listaRetorno = commandsListD

  if(len(commandsListD) != len(listaHandlesRetornadosP)) :

    print("Erro! Inconsistencia na substituicao de parametros dos comandos dependentes")
    return([-1])

  else :   
    i = 0
    for row in commandsListD :
      rowAux = row	
      listaRetorno[i] = rowAux.replace("?", str(listaHandlesRetornadosP[i]))
      i += 1

  return listaRetorno   


def atualizaListaRetorno(listaAtualizacaoHandlesP, listaHandlesRetornadosP) :

  listaRetorno = list()

  if(len(listaAtualizacaoHandlesP) != len(listaHandlesRetornadosP)) :

    print("Erro! Inconsistencia na passagem de parametros")
    return([-1])

  else :  
 
    i = 0
    for row in listaHandlesRetornadosP :
      listaRetorno.append([listaAtualizacaoHandlesP[i][0], row])
      i += 1

  return listaRetorno   


def validaGrupo(listaGruposRegistradosP, groupIdP, dropIdentificadorP, listaGruposP, arquiteturaP) :

  #lista de grupos [ [-1, [2,3,4], -1, -1 ] ] [ [RID, lista de portas, handle_node, handle_associate] ]

  searchP = False
  arquiteturaR = ""
  
  if((groupIdP == -1) and (dropIdentificadorP == 1)) :
    print("Drop invalido")	
    return False #drop invalido

  if((groupIdP != -1) and (dropIdentificadorP == 0)) :
    print("Insercao invalida. Tem que ser gerada automaticamente")	
    return False #insercao invalida. tem que ser gerada automaticamente

  if ((len(listaGruposRegistradosP) == 0) and (groupIdP != -1)) :
    print("Insercao invalida. Tem que ser gerada de forma automatica pelo switch")	
    return False #Insercao tem que ser automatica pelo switch

  for rowLista in listaGruposRegistradosP :
    if (rowLista[0] == groupIdP) :
      searchP = True
      if(arquiteturaP != rowLista[1]) :
	print("Identificador do grupo pertence a outra arquitetura")	
        return False #Identificador de grupo pertence a outra arquitetura

  if((searchP) and (dropIdentificadorP==0)) :
    print("Insercao invalida")	
    return False #insercao invalida

  for rowListaGrupos in listaGruposP :
    #if rowListaGrupos[0] != -1 :
    #  print("RID e compartilhado")	
    #  return False #RID e compartilhado
    if len(rowListaGrupos[1]) == 0 :
      print("Numero de portas invalido")	
      return False #Numero de portas invalido
    elif ((rowListaGrupos[2] == -1) and (dropIdentificadorP == 1)) : #nao entendi.
      print("Drop invalido.")		
      return False #Drop invalido    
      
  return True  


def buscaTuplaInList(searchListP, contentP, columnNumberP, option) :

  search = False
	
  for row in searchListP :

    if ( ( (row[columnNumberP[0]] == contentP[0]) and (option == 1)) or

         ( 
 	   (row[columnNumberP[0]] == contentP[0]) and
	   (row[columnNumberP[1]] == contentP[1]) and
	   (option == 2)
          ) ) :
	
      search = True
      listResp = row
      break

  return (-1,) if not search else row

#devolve uma tupla, o primeiro elemento e o status da execucao do comando e o segundo e uma lista de respostas
def runCommandP4(rawData) :  
   
  global listaGruposRegistrados
 
  listaResposta = list()  

  statusResposta = STATUS_SUCESSO

  if len(rawData) == 0 :
    print("Erro! Inconsistencia dos dados recebidos.")
    return((ERRO_INCONSISTENCIA_DADOS, []))

  GroupId = -1

  for rawDataLine in rawData : 

    commandsList  = list()
    commandsListD = list()
    handlesList   = list() 

    (arquitecture,
     geradorPacketId, 
     switch, 
     thriftPort, 
     p4Command) = (rawDataLine[0], #arquitecture
  	           rawDataLine[1], #geradorPacketId
	  	   rawDataLine[2], #switch
  	    	   rawDataLine[3], #thrift-port  
	           rawDataLine[4]) #p4Command

    print("Architetura: %s %s" %(arquitecture, hex(arquitecture)))

    arquiteturaDs = arquiteturaRequisitora(arquitecture)

    #acho que o if abaixo esta com problemas, porque tem duas respostas distintas, uma para table_add e outra para mc_add
    #portanto primeiro quem que testar qual o tipo de requisicao para depois dar a resposta(mudar)
    if(arquiteturaDs == "-1") :
      print("Arquitetura invalida.")
      listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_ID_ARQUITETURA]) 
      statusResposta = STATUS_FALHA
      continue
      #return((ERRO_ID_ARQUITETURA, []))      

    print("*************************Arquitetura requisitora: ", arquiteturaDs, " Identificador da primitiva: ", str(rawDataLine[1])) 

    #acho que o if abaixo esta com problemas, porque tem duas respostas distintas, uma para table_add e outra para mc_add
    #portanto primeiro quem que testar qual o tipo de requisicao para depois dar a resposta (mudar)
    if( (switch != SWITCH_CORRENTE) or (thriftPort != 9090) ) :
      print("Essa requisicao nao pertence a esse switch, e do switch %s porta %s", switch, port)	
      listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_SWITCH_PORT]) 
      statusResposta = STATUS_FALHA
      continue
      #return((ERRO_SWITCH_PORT, []))
          
    if p4Command == TABLE_ADD_COMMAND : #TABLE_ADD E TABLE_MODIFY_WKEY

      print("Comeco da execucao TABLE_ADD_MODIFY")

      tableDeletekeyCommandS = ""
      tableAddCommandS = ""
      actionsListString=""

      (tableName,
       KeysList,
       actionsList,
       parametersList,
       dropIdentificator) = (rawDataLine[5], #nome completo da tabela
	    		     rawDataLine[6], #lista de chaves
	    		     rawDataLine[7], #lista de acoes
	    		     rawDataLine[8], #lista de parametros das acoes
	    		     rawDataLine[9]) #identificador de drop

      if len(rawDataLine[6]) == 0 :
        print("Erro! Envio de chaves invalida")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_LISTA_CHAVES]) 
        statusResposta = STATUS_FALHA
        continue
	#return((ERRO_LISTA_CHAVES, []))

      keysListString = " ".join(rawDataLine[6])
            	 	
      actionsListString = retornaAcoesParametrosString(rawDataLine[7], rawDataLine[8], GroupId)

      if actionsListString == "-1" :
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_LISTA_ACOES]) 
	statusResposta = STATUS_FALHA
        continue
	#return((ERRO_LISTA_ACOES, []))

      #comando assign_device
      #sempre executar com um gerador diferente, para criar varios arquivos, para permitir recebimento de varias requisicoes, ex. arquivo1 arquivo2 arquivo3, etc
      comandoAD = montaComandoAD(rawDataLine[3]) 
      if comandoAD == "-1" :
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_THRIFT_PORT]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_THRIFT_PORT, []))
         	  	      
      commandsList.append(comandoAD)	
      	 		
      if (dropIdentificator in [0,1]) :

        if (dropIdentificator == 1) :
	            
          commandsList.append(montaComandoTDW(rawDataLine[5], keysListString))
          	            
      else :
        print('Erro! Identificador de Drop esta fora da faixa.')
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_FAIXA_IDENTIFICADOR_DROP]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_FAIXA_IDENTIFICADOR_DROP, []))	

      commandsList.append(montaComandoTA(rawDataLine[5], keysListString, actionsListString))
      
      print("Comeco da execucao")
      
      for rowCommands in commandsList :

        print(rowCommands)	
      
      #muito provavelmente essa formatacao da lista e porque vou colocar o conteudo dessa lista em um arquivo
      commandsListFile = organizaListaParaExecucao(commandsList)      
            	      	 	
      file = open("commandTA.swt","w")
      file.writelines(commandsListFile)      
      file.close()

      cmdTA = CAMINHO_PI_CLI_BMV2 + "pi_CLI_bmv2 -c " + CAMINHO_JSON_FILE + NOME_ARQUIVO_JSON + " < " + CAMINHO_SWT_AT + "commandTA.swt"

      result = os.popen(cmdTA, 'r', 256).read()     
      
      print("*********** resultado da operacao: ", result)

      listaHandlesRetornados = retornaHandlesList(result)

      print("Lista de Handles: ", listaHandlesRetornados)

      if(listaHandlesRetornados[0] == -1) :
        print("Erro na execucao do comando de encaminhamento")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_EXECUCAO_COMANDO]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_EXECUCAO_COMANDO, []))
             
      listaResposta.append ([rawDataLine[0], #arquitecture
    	                     rawDataLine[1], #geradorPacketId
    	  	             rawDataLine[2], #switch
  	    	             rawDataLine[3], #thrift-port  
	                     rawDataLine[4], #p4Command
			     listaHandlesRetornados, #handle do table_add
			     STATUS_SUCESSO]) #status da execucao do comando P4

      print("lista de respostas: ", listaResposta)
			      				         
      print("Fim da execucao do comando TABLE_ADD")

    elif p4Command == MC_ADD_COMMAND :  #MC_MGRP_CREATE e MC_MGRP_UPDATE    
      
      (GroupId,				     #[[2176, 1, "s01", 9090, 2, 1, [[-1, [2], -1, -1]], 0]	
       listaGrupos, 			     #informacoes necessarias para configurar o grupo
       dropIdentificator) = (rawDataLine[5], #identificador do grupo #modificado
	    		     rawDataLine[6], #lista de grupos [ [-1, [2,3,4], -1, -1 ] ] [ [RID, lista de portas, handle_node, handle_associate] ]
	    		     rawDataLine[7]) #identificador de drop

      if len(rawDataLine[6]) == 0 :
        print("Erro! Configuracao de grupos invalida")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], -1, ERRO_LISTA_PORTAS]) 
	statusResposta = STATUS_FALHA
        continue
	#return((ERRO_LISTA_PORTAS, []))

      if(not validaGrupo(listaGruposRegistrados, GroupId, dropIdentificator, listaGrupos, rawDataLine[0])) :
	print("Erro! Grupo invalido")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], -1, ERRO_VALIDACAO_GRUPO]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_VALIDACAO_GRUPO, []))  
       
      #[[2176, 2, "s01", 9090, 2, 2, [[3, [2, 3], 0, -1]], 1], [2176, 2, "s01", 9090, 1, "FIXP_Switch_Ingress.etarch_forward", ["60:c5:59:0f:72:ee"], ["FIXP_Switch_Ingress.etarch_SetSpec_Group"], [[2]], 1]]

      #lista AtualizacaoHandles e a listaGrupos com o Rid do no atualizado
      (commandsList, commandsListD, listaAtualizacaoHandles, GroupId) = montaComandoMC_ADD_MODIFY(GroupId, listaGrupos, dropIdentificator)     
      
      print("Comeco da execucao MC_ADD_MODIFY")
      
      for rowCommands in commandsList :

        print(rowCommands)	

      for rowCommands in commandsListD :

        print(rowCommands)	

      commandsListFile  = organizaListaParaExecucao(commandsList)      

      file = open("commandMCA.swt","w")
      file.writelines(commandsListFile)      
      file.close()

      cmdMCA = CAMINHO_SSWITCH_CLI + "sswitch_CLI --thrift-port " + str(rawDataLine[3]) + " < commandMCA.swt "
      #parametros: comando a ser executado, modo r de leitura, 256 e o tamanho do buffer de saida
      #o metodo retorna um objeto que e o arquivo aberto conectado ao pipe, portanto read vai permitir ler esse arquivo
      #result possui o resultado do comando
      result = os.popen(cmdMCA, 'r', 256).read()     

      print("*********** resultado da operacao 1: ", result)

      listaHandlesRetornados = retornaHandlesList(result, "\n") #cada handle de no retornado equivale a um item RID recebido

      listaHandlesMCA = atualizaListaRetorno(listaAtualizacaoHandles, listaHandlesRetornados) #acho que nao precisa
      
      if(listaAtualizacaoHandles[0] == -1) :
        print("Erro na execucao da atualizacao dos handles de resposta")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], -1, ERRO_ATUALIZACAO_HANDLES]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_ATUALIZACAO_HANDLES, []))

      print("Lista de Handles: ", listaHandlesRetornados) #handle do comando node_create     
      print("Lista de Atualizacao Handles: ", listaAtualizacaoHandles) #em uma operacao anterior, atualizou o rid do comando node_create
      print("Lista de Handles de retorno (MCA): ", listaHandlesMCA)

      print("CommandListD: ", commandsListD)
      commandsListD = substituiParametrosCD(commandsListD, listaHandlesRetornados)

      if commandsListD[0] == -1 :
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], -1, ERRO_PARAMETROS_COMANDOS_DEPENDENTES]) 
	statusResposta = STATUS_FALHA
        continue
        #return ((ERRO_PARAMETROS_COMANDOS_DEPENDENTES, []))

      print("CommandListD1: ", commandsListD) 

      commandsListFileD = organizaListaParaExecucao(commandsListD)                    	

      file = open("commandMCAD.swt","w")
      file.writelines(commandsListFileD)      
      file.close()

      cmdMCAD = CAMINHO_SSWITCH_CLI + "sswitch_CLI --thrift-port " + str(rawDataLine[3]) + " < commandMCAD.swt "
      result  = os.popen(cmdMCAD, 'r', 256).read()     
      #parei aqui
      print("*********** resultado da operacao 2: ", result)

      if(listaHandlesRetornados[0] == -1) : 
        print("Erro na execucao do comando de encaminhamento")
        listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], -1, ERRO_EXECUCAO_COMANDO]) 
	statusResposta = STATUS_FALHA
        continue
        #return((ERRO_EXECUCAO_COMANDO, []))

	#montar lista de handles de resposta
      #listaHandlesRetornados.insert(0, ) #primeiro item da lista e o RID e segundo(ja colocado) e o node handle
      #listaHandlesRetornados.append(GroupId) #ultimo(terceiro) item da lista e o handler (identificador do grupo)

      listaResposta.append ([rawDataLine[0], #arquitecture
    	                     rawDataLine[1], #geradorPacketId
    	  	             rawDataLine[2], #switch
  	    	             rawDataLine[3], #thrift-port  
	                     rawDataLine[4], #p4Command
			     listaHandlesMCA, #handle do MC_ADD_COMMAND [RID, node handle]) (lista de inteiros)
			     GroupId,         #handle do grupo (identificador do grupo criado) (inteiro)	
			     STATUS_SUCESSO]) #status da execucao do comando P4
      
      #busca esta errada, na minha concepcao, tinha que ser uma busca que tem como chave apenas o grupo, nao pode existir grupos repetidos, ou seja,
      #o grupo nao e por arquitetura, ele tem que ser uma pk de todas as arquiteturas
      if buscaTuplaInList(listaGruposRegistrados,
                          [GroupId, rawDataLine[0]], 
			  [0, 1],
                          2) == (-1,) :

	#listaGruposRegistrados equivale a uma lista de lista de [[ groupId, rawDataline[0](arquitetura) ]]
        listaGruposRegistrados.append([GroupId, rawDataLine[0]])

      print("Lista de grupos registrados: ", listaGruposRegistrados)

      print("lista de respostas: ", listaResposta)

      print("Fim da execucao do comando MC_ADD_MODIFY")

      #Parei o desenvolvimento no envio de resposta da requisicao de encaminhamento
	      	    
    else :

      print("ERRO! Comando P4 ainda nao configurado.")
      listaResposta.append ([rawDataLine[0],  rawDataLine[1], rawDataLine[2], rawDataLine[3], rawDataLine[4], [], ERRO_FAIXA_COMANDO]) 
      statusResposta = STATUS_FALHA
      continue
      #return((ERRO_FAIXA_COMANDO, []))


  return(statusResposta, listaResposta)

def primitiveSend(listaResposta) :

  print("Inicio do envio")

  #dadoSerializado = json.dumps(listaResposta)
  dadoSerializado = '/*' + json.dumps(listaResposta) + '*/'

  print("Dado serializado: ", dadoSerializado)

  pkt = Ether(src='FIXP\x00\x00', dst='SWITCH', type=ARQUITETURA_FIXP)
  pkt = pkt / Raw(load = dadoSerializado)
  sendp(pkt, iface=I_FACE, verbose=False)

  print("Final do envio")

def validaSwitch(rawData) :

  if(rawData[0][2] == SWITCH_CORRENTE) :

    return True

  return False

def validaArquiteturaEncapsulada(arquiteturaEncapsuladaP) :

  print("Arquitetura encapsulada: ", arquiteturaEncapsuladaP)

  if arquiteturaEncapsuladaP in [int(ARQUITETURA_IPV4,16),
				 int(ARQUITETURA_ETARCH,16),
				 int(ARQUITETURA_FIXP_S_H,16),
				 int(ARQUITETURA_NG,16),
 				 int(ARQUITETURA_NG_SIMULACAO,16)] :

    return True

  return False
  			  			  			   
def handle_pkt(pkt):

  if Ether in pkt:

    if pkt[Ether].type == ARQUITETURA_FIXP and pkt[Ether].dst == '46:49:58:50:00:00' : #FIXP (CONTROLLER TO SWITCH)
     
      print("***************** INICIO DE REQUISICAO DE MODIFICACOES DE ENCAMINHAMENTO")

      #rawData = json.loads(pkt[Raw].load) 
      rawData = json.loads(pkt[Raw].load[(pkt[Raw].load.find('/*')+2):pkt[Raw].load.find('*/')]) #serializacao modificada

      if len(rawData) != 0 :

        if len(rawData[0]) != 0 :

          if ((validaSwitch(rawData)) and (validaArquiteturaEncapsulada(rawData[0][0]))):
      
            (status, listaResposta) = runCommandP4(rawData)	

            primitiveSend(listaResposta)          

          else :
  
            print("Pacote descartado, pois o MOD_FLOW nao PODE ser executado nesse SWITCH")

        else :

          print('Erro! Ha inconsistencia dos dados recebidos! ')

      else :

        print('Erro! Ha inconsistencia dos dados recebidos! ')

		          
def main():

  print "sniffing " + I_FACE

  sys.stdout.flush()

  sniff(iface=I_FACE, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
  main()
