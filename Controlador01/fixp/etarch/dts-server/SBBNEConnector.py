#recomeco dos trabalhos: 21/02/2020
#!/usr/local/bin/python

#CONTROLADOR ETARCH VERSAO 04

#desligou switch, tem que desligar o controlador e vice-versa, pois as estruturas de armazenamento estao em 
#estrutura de dados e nao em banco de dados

# -*- coding: utf-8 -*-

#ver dependencias de classe entre leituras de primitiva distintas.
#o ideal e fechar as classes depois de sua utilizacao e transformas as estruturas de dados em variaveis globais

from protocol import dts_pb2, etcp_pb2, dtscp_pb2
from dts_wire import buffer_splitter

import itertools
import hashlib

import socket
import struct
import fcntl
import sys
import json

REDE_FISICA_ATUAL = 4

REDE_FISICA_VERSAO_003 = 3
REDE_FISICA_VERSAO_004 = 4

ARQUITETURA_ETARCH_H = 0x0880
ARQUITETURA_ETARCH_H_S = "\x08\x80"
ARQUITETURA_ETARCH_H_U = u"\x08\x80"
ARQUITETURA_FIXP_H   = 0x0900
ARQUITETURA_FIXP_H_S   = "\x09\x00"
ARQUITETURA_ETARCH_S = "0880"

ARQUITETURA_ETARCH_D = 2176

FLAG_DEPENDENCIA_GRUPO = 1

COMMAND_TABLE_ADD = 1 #ENTRADA NA TABELA DA ETARCH
COMMAND_MC_ADD    = 2 #GERENCIAMENTOS DE GRUPOS

dictionaryRegisterEntity = dict()

#workspaceRegisterDictionary = dict()

workspaceEntityAttachList = list()

#0 identificador
#1 titulo do workspace
#2 hash de utilizacao do workspace					      
#3 handle do table_add retornado
#4 entidade proprietaria
workspaceRegisterList = list()

#0 identificador do workspace
#1 switch
#2 [ [RID, lista de portas, handle_node, handle_associate] ]
#3 handle_group
#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
forwardingRulesByWorkspace = list()

geradorPacketId = 0

#Apenas para acompanhemento, traces de teste
geradorRecebimento = 1 

#Returns mac addr for given interface
def getHwAddr(ifname):
	print("teste")
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	

	#ioctl. executa instrucao do so, 0x8927 obter endereco de hardware
	#fileno. passa identificador do s

 	#print("ifname: ", ifname)
	print("ifname: ", ifname)
	print("ifname15: ", ifname[:15])
	print("struct.pack: ", struct.pack('256s', ifname[:15]))	

	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
	print("info: ", info)	
	print("len(info", len(info))
	print("len(info2", len("eth0\x00\x00\x00"))
	print("len(info", info[18:24])		
	return info[18:24]

class DTSSocket(socket.socket):
	def __init__(self, iface, etherType):
		# Ethertype of MEHAR

		print("iface teste ", iface);

		#ETH_MEHAR = ARQUITETURA_ETARCH_H

		#O correto seria a utilizacao da biblioteca BPF para construir os filtros
		#http://allanrbo.blogspot.com/2011/12/raw-sockets-with-bpf-in-python.html
		#verificar comentarios do link acima.

		ETH_MEHAR = etherType

		# Creates a MEHAR socket
		socket.socket.__init__(self, socket.AF_PACKET,
				       socket.SOCK_RAW, ETH_MEHAR);

		# Binds to one specific interface, while nobody cares to define
		# a substitute to local IP route table. Of course, an efficient
		# global routing algorithm is of minor importance when thinking
		# something to replace TCP/IP.
		#self.bind((iface, ETH_MEHAR))
		self.bind((iface, ETH_MEHAR))
		# Set promiscuous mode...

		# Kernel constants
		SIOGIFINDEX = 0x8933

		SOL_PACKET = 263
		PACKET_ADD_MEMBERSHIP = 1
		PACKET_MR_PROMISC = 1

		# Find out device index, would be easier in Python 3 that has
		# socket.if_nametoindex() function...
		ifr = iface + "\0"*(20 - len(iface))
		r = fcntl.ioctl(self.fileno(), SIOGIFINDEX, ifr)
		ifidx = struct.unpack("16sI", r)[1]

		# Request promiscuous mode
		packet_mreq = struct.pack("IHH8s", ifidx, PACKET_MR_PROMISC,
					  6, "\0"*6)
		self.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)

		# For generating ids:
		self.id_counter = itertools.count()

	def send(self, addr, ethertypeP, switch, port, *msg_bufs):
		# TODO: validate address size...

		# Ethertype of MEHAR

		print("executando o send")
		#ethertype = "\x08\x80"

		byte_seq = itertools.chain((addr, ethertypeP), switch, port, msg_bufs)
		print("Byte seq: {}", byte_seq)
		#print('Byte seq: ', ''.join(byte_seq))
		#return socket.socket.send(self, ''.join(byte_seq))
		#return socket.socket.send(self, ''.join(byte_seq))
		return socket.socket.send(self, ''.join(byte_seq))
		#return self.send(self, ''.join(byte_seq))
		#resp = self.recv(1518)
		#return 1

	def send_all(self, addr, msg_buffer):
		sent = 0
		while sent < len(msg_buffer):
			sent += self.send(addr, msg_buffer[sent:])


	def recvFilter(self):
		global geradorRecebimento
		while True:
			# TODO: get interface's MTU instead of hardcoding
			print("comeco do recebimento: ", geradorRecebimento)
			geradorRecebimento+=1
			resp = self.recv(1518)
			print("fim do recebimento", resp)
			print("Resp 0:6", resp[0:6])
			print("Resp 6:12", resp[6:12])
			print("Resp 12-14", resp[12:14])
			print("Resp 0-14", resp[0:14])
			print("Resp 14:", resp[14:])
			#return resp
			#print ''.join( [ "%02X " % ord( x ) for x in resp[:12]] ).strip()
			if (resp[0:6] == "DTS\x00\x00\x00" and resp[12:14] == ARQUITETURA_ETARCH_H_S):
				return (resp[0:14], resp[14:])
				# There is no need to check ethertype because
				# the socket interface will do it for us.
			#return resp[14:] # Strip ETH header/footer

	def recvPrimitiveForwardingFilter(self):
		
		global geradorRecebimento
		
		while True:
			# TODO: get interface's MTU instead of hardcoding
			print("comeco do recebimento: ", geradorRecebimento)
			geradorRecebimento+=1
			resp = self.recv(1518)			
			print("fim do recebimento", resp)
			print("Resp 0:6", resp[0:6])
			print("Resp 6:12", resp[6:12])
			print("Resp 12-14", resp[12:14])
			print("Resp 0-14", resp[0:14])
			print("Resp 14:", resp[14:])
			#return resp
			#print ''.join( [ "%02X " % ord( x ) for x in resp[:12]] ).strip()
			
			#arquiteturaEnc = json.loads(resp[14:])[0][0]

			arquiteturaEnc = json.loads(resp[14:][resp[14:].find('/*')+2:resp[14:].find('*/')])[0][0] #serializacao modificada

			if (resp[0:6] == "SWITCH" and resp[6:12]=='FIXP\x00\x00' and resp[12:14] == ARQUITETURA_FIXP_H_S and arquiteturaEnc == ARQUITETURA_ETARCH_D):
				return (resp[0:14], resp[14:])

				# There is no need to check ethertype because
				# the socket interface will do it for us.
			#return resp[14:] # Strip ETH header/footer

class SBBNEConnector(object):

	def __init__(self, iface):
		self.iface = iface
		#pelo que tudo indica tive que criar dua portas para cada tipo de protocolo
		#e nao por aplicacao, porque pelo que tudo indica
		#a criacao feita juntamente no bind com o EtherType filtra o tipo de ethernet
		#no kernel do computador. o controlador poderia ter sido feito de uma forma
		#diferente, com scapy, mas foi feito conforme chat.py
		self.sock  = DTSSocket(iface, ARQUITETURA_ETARCH_H)
		self.sock1 = DTSSocket(iface, ARQUITETURA_FIXP_H)
		self.primitiveParser()

	'''	
	def __del__(self):
		if self.registered:
			self.unregister()
		self.socket.close()
	'''

	def responseSend(self, switch, port, ethernetHeader, reqObj, status):
	
		sendAddr = "\xff\xff\xff\xff\xff\xff" + ethernetHeader[0:6]

		print("sendAddr: ", sendAddr)		

		respObj = dts_pb2.ControlResponse()
		respObj.status = status
		respObj.request_id = reqObj.id
		#mudar essa chamada. colocar no campo abaixo o titulo da entidade requisitora
		#abaixo teria que ser modificado para:
		#quando acabar o estudo, faco a modificacao
		#respObj.srcTitle = ethernetHeader[6:12]
		respObj.srcTitle = "DTSA"

		respObjSer = respObj.SerializeToString()
		#caso modificar esse controlador para realizar packet_out automaticamente, tem que colocar a arquitetura.
		print("switch: ", struct.pack('3s', switch.encode('utf-8')))
		print("porta: ", struct.pack('>H', port))
		print("len: ", struct.pack("<H", len(respObjSer)))
		print("Objeto de resposta serial: %s", respObjSer)
				
		#send(self, addr, ethertypeP, switch, port, *msg_bufs)

		sendRet = self.sock.send(sendAddr, 
					 ARQUITETURA_ETARCH_H_S,
					 struct.pack('3s', switch.encode('utf-8')),
					 struct.pack('>H', port),	
					 struct.pack("<H", len(respObjSer)), 
					 respObjSer)

		return sendRet

	#recebe arquitectureP -> decimal - id do workspace da estrutura, identificador  - objeto SBBWorkspaceManager
	def sendForwardingRules(self, arquitectureP, workspaceIdP, worAttObjP):

		global geradorPacketId
	
		sendData = list()

		sendAddr = "FIXP\x00\x00" + "DTSA\x00\x00"

		'''
		print("sendAddr: ", sendAddr)		
		print("switch: ", struct.pack('3s', switch.encode('utf-8')))
		print("porta: ", struct.pack('<H', port))
		print("len: ", struct.pack("<H", len(respObjSer)))
		print("Objeto de resposta serial: %s", respObjSer)
		'''	
		
		#0 identificador do workspace
		#1 switch                          [1, 's01', [ [1, [2,3,4], -1, -1 ] ], -1, 0, 9090]
		#2 [ [RID, lista de portas, handle_node, handle_associate] ]
		#3 handle_group
		#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
		#5 thrift-port
		#6 executa_switch

		statusAtualizacaoList = list()

		for forwardingRulesSearch in buscamMultipleTuplaInList(forwardingRulesByWorkspace, 
					         	               [workspaceIdP, 1], 
    							               [0, 6], 
							               2) :

		        listaPortas = list()

			if forwardingRulesSearch[0] == -1 :
			
				print("Erro! workspace %d nao configurado na estrutura no vetor de encaminhamentos" %workspaceIdP)
				exit(1)

			else :

				#if(forwardingRulesSearch[4] == 0 :

				#inserir todos os comandos

				geradorPacketId += 1					
				'''	
		  		registeredWorkspace = buscaTuplaInList(workspaceRegisterList,
                                                                      [workspaceIdP], 
								       [0], 
								       1)
				'''

				registeredWorkspace = buscaTuplaInList(workspaceRegisterList,
								       [workspaceIdP],
                                                                       [0],
                                                                       1)  
				
				if(-1 == registeredWorkspace[0]):
					print("ERRO! INCONSISTENCIA! Worspace %d nao foi cadastrado anteriormente" %workspaceIdP)
					exit(1)
				
				print("Vetor de encaminhamentos original: ", forwardingRulesByWorkspace)
				print("Linhas do vetor de encaminhamentos original: ", forwardingRulesSearch)
				print("Vetor do workspace retornado: ", registeredWorkspace)

				#analisar a questao do parametro drop, ultimo parametro abaixo

				#print("conteudo " + str(registeredWorkspace[2]))
				#teste = u''+registeredWorkspace[2]+''

				print("architecture ", arquitectureP)
				print("chave ", u'`\xc5Y\x0fr\xee'.encode('utf-8'))
				print("chave2 string ", registeredWorkspace[2])
				
				#print("chave2 ", (u''+str(registeredWorkspace[2])+'').encode('utf-8'))

				#print("ethertype: ", "\x08\x80".decode('utf-8'))
				
				#print("ethertype: ", u'\x08\x80'.encode('utf-8'))

				#0 identificador do workspace
				#1 switch                          [1, 's01', [ [-1, [2,3,4], -1, -1 ] ], -1, 0, 9090]
				#2 [ [RID, lista de portas, handle_node, handle_associate] ]
				#3 handle_group
				#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
				#5 thrift-port
			        #6 executa_switch
				
				#parei na lista de portas	

				print("ListaPortas: ", listaPortas)
				
				#passagem por referencia
				sendData = []
				
				#pacotes do fixp -> parece ser os pacotes do fixp

				sendData.append([arquitectureP,   #inteiro decimal
						geradorPacketId,  #inteiro decimal
						forwardingRulesSearch[1], #switch string 's01','s02', ...
						forwardingRulesSearch[5], #thrift-port 'inteiro decimal: 9090 
						COMMAND_MC_ADD, #comando a ser executado (inteiro decimal)
						forwardingRulesSearch[3], #grupo a ser criado #modificado
						forwardingRulesSearch[2], #passa o conjunto necessario para dropar e adicionar grupos
						forwardingRulesSearch[4]]) #identificador de drop 0. nao dropa nada, 1. dropa   ..dropar utilizando a chave inteiro decimal)

				#abaixo, o certo seria fazer dependencia dos parametros da acao do grupo gerado pelo switch
				#para fins de prova de conceito, e como se fizessemos uma divisao de identificadores de grupo por arquitetura
				#como o grupo passara a ser criado dinamicamente pelo switch, nao havera problemas	
			
				#acho que o bmv2 nao aceita dropar o grupo sem dropar primeiramente a tabela
				#que utiliza o grupo
				if(registeredWorkspace[3] != -1) :
				  statusDrop = 1
				else :				
				  statusDrop = 0										
				
				sendData.append([arquitectureP,   #inteiro decimal
						geradorPacketId,  #inteiro decimal
						forwardingRulesSearch[1], #switch string 's01','s02', ...
						forwardingRulesSearch[5], #thrift-port 'inteiro decimal: 9090 
						COMMAND_TABLE_ADD, #comando a ser executado (inteiro decimal)
						"FIXP_Switch_Ingress.etarch_forward", #nome completo da tabela (string)
						[registeredWorkspace[2]], #lista de chaves 
						#[u'`\xc5Y\x0fr\xee'.encode('utf-8')], #lista de chaves (string)
						#[u''+registeredWorkspace[2]+''.encode('utf-8')], #lista de chaves 
						["FIXP_Switch_Ingress.etarch_SetSpec_Group"], #lista de nomes completos da acoes (string)
						[[forwardingRulesSearch[3]]], #lista de parametros (Cada item da lista equivale ao seu item equivalente na lista de acoes string #modificado
						#statusDrop]) #identificador de drop 0. nao dropa nada, 1. dropa   ..dropar utilizando a chave inteiro decimal) #modificado versao 04
						forwardingRulesSearch[4]]) #esta mandando o modify_id para saber se foi modificado ou nao ,se foi modificado a ordem e apagar tudo e refazer as tabelas ou grupos

				
				print("sendData: ", sendData)

				#jasonString = json.dumps(sendData)

				#parei aqui. Pensei que a escolha do switch seria um problema para a camada de abstracao, mas nao sera!

				jasonString = '/*' + json.dumps(sendData) + '*/' #serializacao modificada, acho que por conta do minimo de 46 bytes em raw[load]
				
				print("jasonString: ", jasonString)				
							
				#send(self, addr, ethertypeP, switch, port, *msg_bufs):

				sendRet = self.sock1.send(sendAddr, 
						  	  ARQUITETURA_FIXP_H_S,
							  '',
							  '',
							  jasonString)
						          #struct.pack('3s', switch.encode('utf-8')), #switch
							  #struct.pack('>H', port),	
							  #struct.pack("<H", len(respObjSer)), 
							  #espObjSer)

				if sendRet <= 0 :
				  print("Erro no envio do protocolo FIXP")
				  return(dts_pb2.ControlResponse.FAILURE, "-1")
				
				print("Fim do envio (status): ", sendRet)	

				ethernetHeader, rawData = self.sock1.recvPrimitiveForwardingFilter()

				print("Ethernet header Forwarding: ", ethernetHeader)
				print("Raw data Forwarding: ", rawData)	
				
				#atualizar depois .. classe desconhecida
				statusAtualizacao = worAttObjP.updateForwardingRules(json.loads(rawData[rawData.find('/*')+2:rawData.find('*/')]), workspaceIdP)

				if statusAtualizacao == -1 :
				  print("ERRO! Houve erro na execucao de comandos de encaminhamento! ")				

				statusAtualizacaoList.append(statusAtualizacao)
				
				#if statusAtualizacao == -1 :
				#  print("ERRO! Atualizacao da estrutura de dados inconsistente! ")
				#  exit(1)

				#serializar resposta e atualizar banco de dados
			        
																													
		#return (sendRet, json.loads(rawData)) 

		return (sendRet, json.loads(rawData[rawData.find('/*')+2:rawData.find('*/')]), statusAtualizacaoList) #serializacao modificada   
		

	#def addForwardingRules(self, 
	#a abertura do socket com Ethertype preve a captacao apenas de pacotes etarch e fixp 
	#sock recebendo primitivas etarch e sock1 recebendo primeitivas fixp					
	def primitiveParser(self):

		print('********************************** COMECO DA EXECUCAO DO DTSA')

		reqObj = dts_pb2.ControlRequest()
		reqSea = False	

		while not reqSea :
						
			ethernetHeader, rawData = self.sock.recvFilter()

			print("Ethernet header: ", ethernetHeader)
			print("Raw data: ", rawData)			
			
			cont = 0
			
			for msg_buffer in buffer_splitter(rawData):

				print("Mensagem buffer: ",msg_buffer)
				
				if cont == 0 :

					print("************************INICIO DE UMA NOVA REQUISICAO...")
					reqObj.ParseFromString(msg_buffer)
					print("Type: %s" % reqObj.type)
					print("Id: %d" % reqObj.id)
					print("Title: %s"  % reqObj.dstTitle)
				#parei aqui.
				elif cont == 1 :
 
					if reqObj.type == dts_pb2.ControlRequest.ETCP_ENTITY_REGISTER :
	
						print("************************************** Registrando nova entidade no SBB Entity Manager...")
								
						reqEntReg = etcp_pb2.EntityRegister()
						reqEntReg.ParseFromString(msg_buffer)
						
						print("Titulo: %s" %reqEntReg.title)
											
						entRegObj = SBBEntityManager(reqEntReg)
						status = entRegObj.entityRegister()

						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
												
						#envia packet_out	#modificado versao 04
						(switch, porta) = topologiaRedeFisica(reqEntReg.title, REDE_FISICA_ATUAL)

						if switch == -1 : #modificadoV4
							print("Erro do envio da primitiva de resposta. Topologia nao cadastrada corretamente!")					
							exit(1)

						else:
						
							if self.responseSend(switch, porta, ethernetHeader, reqObj, status) <= 0 :
								print("Erro do envio da primitiva de resposta")					
								exit(1)
												
						print("Termino de registro da entidade do SBB Entity Manager...")

						#reqSea = True
						break					

						#Montar uma funcao que monta ControlResponse.. todas as SBBs irao
						#utilizar essafuncao... seria legal criar uma biblioteca de 
						#funcoes uteis que serao compartilhadas
						#a classe vai montar 

					elif reqObj.type == dts_pb2.ControlRequest.ETCP_WORKSPACE_CREATE :
	
						print("Criando/Atachando workspace no SBBWorkspaceManager...")
								
						reqWorAttCre = etcp_pb2.WorkspaceCreate()
						reqWorAttCre.ParseFromString(msg_buffer)

						reqWorAtt = etcp_pb2.WorkspaceAttach()
						reqWorAtt.workspace_title = reqWorAttCre.workspace_title
						reqWorAtt.entity_title = reqWorAttCre.entity_title

						
						print("Worskpace: %s" %reqWorAttCre.workspace_title)
						print("Entidade: %s" %reqWorAttCre.entity_title)
						print("Attach_too: %s" %reqWorAttCre.attach_too)
											
						worAttCreObj = SBBWorkspaceManager(reqWorAtt, reqWorAttCre)
						#status = worAttCreObj.workspaceCreate(entRegObj.dictionaryRegisterEntity)
						(status,workspaceId) = worAttCreObj.workspaceCreate()

						print("Status retornado ", status)
						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
						
						if status == dts_pb2.ControlResponse.SUCCESS :

							count = 0
							while ((True) and (count < 3)):

								(sendRet, rawData, statusAtualizacaoList) = self.sendForwardingRules(ARQUITETURA_ETARCH_D, workspaceId, worAttCreObj)

								if sendRet <= 0 :
									print("Erro do envio da primitiva de resposta")
									exit(1)

								#modificado para versao 04
								#statusAtualizacao = worAttCreObj.updateForwardingRules(rawData, workspaceId)

								if (-1 not in statusAtualizacaoList):
									break

								count += 1

							if count == 3 :
								## Nesse momento temos que refazer a estrutura de dados 	
								## (desfazer algo que foi feito, voltar ao original, talvez apagar o que foi feito no switch)
								## Objetivo. Evitar inconsistencia	
								print("Comando nao foi executado corretamente no switch") 

								#break #break de qualquer jeito ate fazer o que esta escrito no bloco abaixo

								#if statusAtualizacao == -1 teria que fazer o loop de novo, ate todas as instrucoes serem executadas
								#com sucesso. ate que o campo modify_id do vetor de encaminhamento fosse 1 ou ate que
								#tentasse por cinco vezes (por exemplo) ... tem que modificar para ficar mais robusto quando a consistencia
								#da minha estrutura de dados e as regras gravadas no switch
												
								#break #posteriormente fazer loop para tratamento de erros
						
						(switch, porta) = topologiaRedeFisica(reqWorAttCre.entity_title, REDE_FISICA_ATUAL)	
						
						if self.responseSend(switch, porta, ethernetHeader, reqObj, status) <= 0 :
							print("Erro do envio da primitiva de resposta")					
							exit(1)
												
						print("Termino de create/attach")
						 						
						#reqSea = True
						break					

						#Montar uma funcao que monta ControlResponse.. todas as SBBs irao
						#utilizar essafuncao... seria legal criar uma biblioteca de 
						#funcoes uteis que serao compartilhadas
						#a classe vai montar 


					elif reqObj.type == dts_pb2.ControlRequest.ETCP_WORKSPACE_ATTACH :
	
						print("Atachando entidade no workspace em SBBWorkspaceManager...")
								
						reqWorAtt = etcp_pb2.WorkspaceAttach()
						reqWorAtt.ParseFromString(msg_buffer)
						
						print("Worskpace: %s" %reqWorAtt.workspace_title)
						print("Entidade: %s" %reqWorAtt.entity_title) #parei aqui.
											
						worAttObj = SBBWorkspaceManager(reqWorAtt, etcp_pb2.WorkspaceCreate())
						#status = worAttObj.workspaceAttach(entRegObj.dictionaryRegisterEntity)
						#status = worAttObj.workspaceAttach()
						(status,workspaceId) = worAttObj.workspaceAttach()

						print("Status retornado %d" %status)

						if status == dts_pb2.ControlResponse.SUCCESS :

							count = 0
							while ((True) and (count < 3)):

								(sendRet, rawData, statusAtualizacaoList) = self.sendForwardingRules(ARQUITETURA_ETARCH_D, workspaceId, worAttObj)

								if sendRet <= 0 :
									print("Erro do envio da primitiva de resposta")
									exit(1)

								#modificado para a versao 04
								#statusAtualizacao = worAttObj.updateForwardingRules(rawData, workspaceId)

								#if statusAtualizacao != -1 :
								#	break

								if (-1 not in statusAtualizacaoList):
									break

								count += 1

							if count == 3 :
								## Nesse momento temos que refazer a estrutura de dados 	
								## (desfazer algo que foi feito, voltar ao original, talvez apagar o que foi feito no switch)
								## Objetivo. Evitar inconsistencia	
								print("Comando nao foi executado corretamente no switch") 

								#break #break de qualquer jeito ate fazer o que esta escrito no bloco abaixo

								#if statusAtualizacao == -1 teria que fazer o loop de novo, ate todas as instrucoes serem executadas
								#com sucesso. ate que o campo modify_id do vetor de encaminhamento fosse 1 ou ate que
								#tentasse por cinco vezes (por exemplo) ... tem que modificar para ficar mais robusto quando a consistencia
								#da minha estrutura de dados e as regras gravadas no switch
												
								#break #posteriormente fazer loop para tratamento de erros

						(switch, porta) = topologiaRedeFisica(reqWorAtt.entity_title, REDE_FISICA_ATUAL)	
						
						if self.responseSend(switch, porta, ethernetHeader, reqObj, status) <=   0 :
							print("Erro do envio da primitiva de resposta")					
							exit(1)
												
						print("Termino do attach")

						#reqSea = True
						break					

						#Montar uma funcao que monta ControlResponse.. todas as SBBs irao
						#utilizar essafuncao... seria legal criar uma biblioteca de 
						#funcoes uteis que serao compartilhadas
						#a classe vai montar 



				elif cont > 1 :
					#A partir daqui as mensagens sao nulas... acho que podem ser desprezadas.
					#Sempre serao so dois contadores... e o que acho
					print("Erro...!")


				cont+=1

				#reqSea = True
				#break;
			
	
			
	'''
		msg = etcp_pb2.EntityRegister()
		msg.title = self.title
		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_ENTITY_REGISTER)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Failed to register entity.")
		self.registered = True
	
	def unregister(self):
		msg = etcp_pb2.EntityUnregister()
		msg.title = self.title
		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_ENTITY_UNREGISTER)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Failed to unregister entity.")
		self.registered = FalseEntity(object)
	'''

class SBBEntityManager(object):

	#chave. Identificador do registro da entidade
	#value. Titulo da entidade	
	

	def __init__(self, reqEntReg):
		self.reqEntReg = reqEntReg
		#SBBEntityManager.dictionaryRegisterEntity = dict()

 	#@property
	#def dictionaryRegisterEntity(self):
	#	return SBBEntityManager.dictionaryRegisterEntity

	def entityRegister(self):

		#try :

		if(self.reqEntReg.title in dictionaryRegisterEntity.values()) :

			print("ERRO! Entidade %s ja foi registrada anteriormente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.FAILURE

		else :
			
			dictionaryRegisterEntity[int(len(dictionaryRegisterEntity)+1)] = self.reqEntReg.title
			
			print("Entidade %s foi registrada corretamente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.SUCCESS

		print("Dictionary de entidades: %s" %dictionaryRegisterEntity)	
		  
		return registerStatus

		#except :

		#	print("Erro inesperado ao registrar entidade %s %s" %(self.reqEntReg.title,sys.exc_info()))
		#	return dts_pb2.ControlResponse.FAILURE
			
			

	#def __del__(self):
	#	if self.registered:
	#		self.unregister()
	#	self.socket.close()
			
	#def unregister(self):
	#	msg = etcp_pb2.EntityUnregister()
	#	msg.title = self.title
	#	res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_ENTITY_UNREGISTER)
	#	if res.status != dts_pb2.ControlResponse.SUCCESS:
	#		raise DTSException("Failed to unregister entity.")
	#	self.registered = False

#retorna posicao do conteudo em uma lista qualquer
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


def buscamMultipleTuplaInList(searchListP, contentP, columnNumberP, option) :

	search = False
	
	for row in searchListP :

		if ( ( (row[columnNumberP[0]] == contentP[0]) and (option == 1)) or
		       ( 
			  (row[columnNumberP[0]] == contentP[0]) and
			  (row[columnNumberP[1]] == contentP[1]) and
			  (option == 2)
		       ) ) :
	
			search = True
			yield row
			
	if not search :
		yield (-1,) 


def buscaIndexInList(searchListP, contentP, columnNumberP, option) :

	search = False

	index = -1
	#option e o numero de parametros que estamos procurando
	for i in range(len(searchListP)) :

		if ( ( (searchListP[i][columnNumberP[0]] == contentP[0]) and (option == 1)) or

		       ( 
			  (searchListP[i][columnNumberP[0]] == contentP[0]) and
			  (searchListP[i][columnNumberP[1]] == contentP[1]) and
			  (option == 2)
		       ) or

		       ( 
			  (searchListP[i][columnNumberP[0]] == contentP[0]) and
			  (searchListP[i][columnNumberP[1]] == contentP[1]) and
			  (searchListP[i][columnNumberP[2]] == contentP[2]) and
			  (option == 3)
		       ) ) :
	
			search = True
			index = i
			break

	return index

#retorna conteudo achado
def AttributeSearch(searchDictionary, contentP, columnNumberP):

	#item() retorna uma lista de tuplas onde a primeira posicao e a chave e a segunda e o valor do dicionario
        #search e cada tupla da lista
        #search[posicao] e o elemento da tupla
	#AtributeSearch retorna a tupla
	for search in searchDictionary.items() :
			
		if search[columnNumberP] == contentP :

			return search

	return (-1,)

#serve para o packet_out... e a topologia
def topologiaRedeFisica(entityP, redeFisica) : #fazer packet out geral

	if redeFisica == REDE_FISICA_VERSAO_003 : #Primeira versao de rede com apenas 1 switch

		if entityP == "e1" :

			return ("s01", 2)		

		elif entityP == "e2" :

			return("s01", 3)

		elif entityP == "e3" :

			return("s01", 4)

		elif entityP == "e4" :

			return("s01", 5)

		elif entityP == "e5" :

			return("s01", 6)

		elif entityP == "e6" :

			return("s01", 7)

	elif redeFisica == REDE_FISICA_VERSAO_004 : #Primeira versao de rede com apenas 1 switch

		if entityP == "e1" :

			return ("s01", 2)		

		elif entityP == "e2" :

			return("s03", 2)

		elif entityP == "e3" :

			return("s05", 2)

		elif entityP == "e4" :

			return("s01", 5)

		elif entityP == "e5" :

			return("s04", 2)

		elif entityP == "e6" :

			return("s02", 2)

		elif entityP == "e7" :

			return("s05", 3)

	return (-1, -1)


class SBBWorkspaceManager(object):	

	def __init__(self, reqWorAtt, reqWorCre):
		self.reqWorAtt = reqWorAtt
		self.reqWorCre = reqWorCre

		#0. Identificador de registro do workspace 
		#1. Titulo do workspace  
		#2. Identificador da entidade
		#SBBWorkspaceManager.worskpaceRegisterDictionary = dict()

		#0. Identificador do workspace
		#1. Identificador da entidade attachada
		#SBBWorkspaceManager.workspaceEntityAttachList = list()

	def updateWorkspaceRegisterList(self, answerP, workspaceIdP) :

		#[[2176, 1, "s01", 9090, 2, [[2, 4]], 2, 0], [2176, 1, "s01", 9090, 1, [0], 3]]

		#0 identificador do workspace
		#1 switch
		#2 [ [RID, lista de portas, handle_node, handle_associate] ]
		#3 handle_group -> preenchido pelos switch ... e o proprio indentificador do grupo
		#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
		#5 thrift-port
		#6 executa_switch

		statusRetorno = dts_pb2.ControlResponse.SUCCESS

		print("WorkspaceRegisterList: ", workspaceRegisterList)

		registerIndex = buscaIndexInList(workspaceRegisterList,
						 [workspaceIdP],
                                                 [0],
                                                 1)  

		print("registerIndex", registerIndex)

		if registerIndex != -1 :

			workspaceRegisterList[registerIndex][3] = answerP[5][0]			

		else :

			print("Lista workspaceRegisterList nao atualizada")
			statusRetorno = -1

		
		print("WorkspaceRegisterList atualizada: ", workspaceRegisterList)	

		return statusRetorno

	def updateForwardingRulesByWorkspace(self, answerP, workspaceIdP) :

		#[[2176, 1, "s01", 9090, 2, [[2, 4]], 2, 0], [2176, 1, "s01", 9090, 1, [], 3]]

		#0 identificador do workspace
		#1 switch
		#2 [ [RID, lista de portas, handle_node, handle_associate] ]
		#3 handle_group -> preenchido pelos switch ... e o proprio indentificador do grupo
		#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
		#5 thrift-port
		#6 executa_switch

		print("forwardingRulesByWorkspace: ", forwardingRulesByWorkspace)
		

	        #a procura e feita por id_workspace, switch e thrift-porta como se fosse a chave desses registros de workspace
		registerIndex = buscaIndexInList(forwardingRulesByWorkspace, 
					 	 [workspaceIdP, answerP[2], answerP[3]], 
					         [0, 1, 5], 
					         3)

		print("registerIndex", registerIndex)

		if registerIndex != -1 :
			
			#posicao 2 da estrutura forwardingRulesByWorkspace e uma lista de listas
			for i in range(len(forwardingRulesByWorkspace[registerIndex][2])) :

				forwardingRulesByWorkspace[registerIndex][2][i][0] = answerP[5][i][0] #atualizacao do RID
				forwardingRulesByWorkspace[registerIndex][2][i][2] = answerP[5][i][1] #atualizacaso do handle node
				#teoricamente nao preciso do handle_associate porque deleto o grupo apenas com a informacao do grupo
				# e do handle_no que no nosso caso vai ser sempre 1 no com uma lista de portas

			forwardingRulesByWorkspace[registerIndex][3] = answerP[6] #atualizacaso do handle group (id do grupo criado)

			forwardingRulesByWorkspace[registerIndex][4] = 1 #atualizadao do modifyId. Quer dizer que este fluxo esta no switch
			forwardingRulesByWorkspace[registerIndex][6] = 0 #atualizacao do executa_switch para 0 (nao executar mais)
							
		else :

			print("Lista nao atualizada")

		
		print("forwardingRulesByWorkspace atualizada: ", forwardingRulesByWorkspace)		

		return registerIndex
			

        def updateForwardingRules(self, rawDataP, workspaceIdP) :

		#[[2176, 1, "s01", 9090, 2, [[2, 4]], 2, 0], [2176, 1, "s01", 9090, 1, [], 3]]

		#0 identificador do workspace
		#1 switch
		#2 [ [RID, lista de portas, handle_node, handle_associate] ]
		#3 handle_group -> preenchido pelos switch ... e o proprio indentificador do grupo
		#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
		#5 thrift-port
		#6 executa_switch
	
		statusRetorno = dts_pb2.ControlResponse.SUCCESS

		for rowRawData in rawDataP :

			if rowRawData[4] == COMMAND_TABLE_ADD :

				if rowRawData[6] == dts_pb2.ControlResponse.SUCCESS :
				
					if self.updateWorkspaceRegisterList(rowRawData, workspaceIdP) == -1 :
						print("Erro! Inconsistencia na estrutura de dados")
						exit(1)												

				else:

					print("Comando nao executado corretamente no switch, erro: %d" %rowRawData[6])
					statusRetorno = -1
				

			elif rowRawData[4] == COMMAND_MC_ADD :

				if rowRawData[7] == dts_pb2.ControlResponse.SUCCESS :

					if self.updateForwardingRulesByWorkspace(rowRawData, workspaceIdP) == -1 :

						print("Erro! Inconsistencia na estrutura de dados")
						exit(1)

				else :
					print("Comando nao executado corretamente no switch, erro: %d" %rowRawData[7])
					statusRetorno = -1
			


		return statusRetorno

	#representa a emulacao da rotina de roteamento
																	
	def roteamentoRedeFisica(self, entityP, redeFisica) :

		if redeFisica == REDE_FISICA_VERSAO_003 : #Primeira versao de rede com apenas 1 switch

			if entityP == "e1" :
					 #switch, port, thift-port
				return [("s01", [2], 9090)]		
	
			elif entityP == "e2" :
		
				return [("s01", [3], 9090)]

			elif entityP == "e3" :

				return [("s01", [4], 9090)]

			elif entityP == "e4" :
	
				return [("s01", [5], 9090)]
	
			elif entityP == "e5" :
	
				return [("s01", [6], 9090)]

			elif entityP == "e6" :
	
				return [("s01", [7], 9090)]

		elif redeFisica == REDE_FISICA_VERSAO_004 : #Primeira versao de rede com apenas 1 switch

			if entityP == "e1" :
					 #switch, port, thift-port
				return [("s01", [2], 9090)]		
	
			elif entityP == "e2" :
		
				return [("s03", [2, 3], 9090), ("s02", [4, 3], 9090), ("s01", [2, 3], 9090)]

			elif entityP == "e3" :

				return [("s05", [2, 5], 9090), ("s01", [2, 3, 4], 9090)]

			elif entityP == "e4" :
	
				return [("s01", [5], 9090)]
	
			elif entityP == "e5" :
	
				return [("s04", [2, 4], 9090), ("s05", [5, 4], 9090), ("s01", [5, 4], 9090)]

			elif entityP == "e6" :
	
				return [("s02", [2, 3], 9090), ("s01", [5, 4, 3], 9090)]

	
		return (-1,)

	#titulo da entidade entityP, id do workspace, rede fisica
	def addForwardingRules(self, entityP, workspaceIdP, redeFisicaP) :
		
		#retorna uma lista de tuplas com switch, lista de portas e thrift-port
		#[("s03", [2, 3], 9090), ("s02", [4, 3], 9090), ("s01", [2, 3], 9090)]
		#para e2 versao 04 return [("s03", [2, 3], 9090), ("s02", [4, 3], 9090), ("s01", [2, 3], 9090)]
		switchesPorts = self.roteamentoRedeFisica(entityP, redeFisicaP)		

		# exemplo de row [("s01", [2], 9090)]
		for row in switchesPorts :
			#parei.juliano
			#ele procura como se fossem chaves se tem forwadingRulesByWorkspace
			#utilizando como chave da procura o workspce, switch, thift-port
			registerIndex = buscaIndexInList(forwardingRulesByWorkspace, #modificado
					 		 [workspaceIdP, row[0], row[2]], 
							 [0, 1, 5], 
							 3)

			print("registerIndex", registerIndex)

			if registerIndex == -1 :

				#0 identificador do workspace
				#1 switch
				#2 [ [RID, lista de portas, handle_node, handle_associate] ]
				#3 handle_group -> preenchido pelos switch ... e o proprio indentificador do grupo
				#4 ModifyId. 0->Executar comandos 1->Apagar tudo e executar comandos novamente
				#5 thrift-port				
			        #6 executa_switch 0. nao executa no switch   1. executa no switch (nao executar no switch desnecessariamente)

				forwardingRulesByWorkspace.append( [workspaceIdP, 		
								    row[0],
							            [[-1, 
								      row[1],
								      -1,
								      -1]],
								    -1,
								     0,
								     row[2], 
								     1]) 	 		 

			else :
			        #row[1] e uma lista de portas
				for portsRow in row[1] :
					#portsRow e uma das portas
					if portsRow not in forwardingRulesByWorkspace[registerIndex][2][0][1] :

						forwardingRulesByWorkspace[registerIndex][2][0][1].append(portsRow)
						#rever abaixo (consertei. ver se deu certo)
						#modify_id e para ver se houve alguma alteracao no registro da chave procurada
						#id do workspace, switch, trift-port, porque se houve alteracao
						#temos que executar esse comando novamente no switch
						forwardingRulesByWorkspace[registerIndex][4] = 1
						forwardingRulesByWorkspace[registerIndex][6] = 1

		print("Vetor de encaminhamentos: ", forwardingRulesByWorkspace)							

	def workspaceCreate(self):
		#try :

		  #if(self.reqWorAtt.workspace_title in workspaceRegisterDictionary.values()) :

		attachStatus = dts_pb2.ControlResponse.SUCCESS
		workspaceId = -1

		registeredEntity = AttributeSearch(dictionaryRegisterEntity, self.reqWorAtt.entity_title, 1)

		if -1 == registeredEntity[0] :

			print("ERRO! Entidade %s nao foi registrada anteriormente" %self.reqWorAtt.entity_title)
			attachStatus = dts_pb2.ControlResponse.FAILURE

		else :

			print("Entidade retornada na criacao", registeredEntity) 

		  
		registeredWorkspace = buscaTuplaInList(workspaceRegisterList, 
						       [self.reqWorAtt.workspace_title], 
						       [1], 
						       1)

		if(-1 != registeredWorkspace[0]) :

			print("ERRO! Worspace %s ja foi criado anteriormente" %self.reqWorAtt.workspace_title)
			createStatus = dts_pb2.ControlResponse.FAILURE

		else :
			
			#workspaceRegisterDictionary[int(len(workspaceRegisterDictionary)+1)] = self.reqWorAtt.workspace_title jujujuju

			if attachStatus == dts_pb2.ControlResponse.SUCCESS :

				workspaceId = (int(len(workspaceRegisterList)+1))
				#chave do workspace - hash do workspace criptografada - 
				chaveWorkspace = ":".join("{:02x}".format(ord(c)) for c in hashlib.sha256(self.reqWorAtt.workspace_title).digest()[:6])				

				workspaceRegisterList.append([workspaceId,
							     self.reqWorAtt.workspace_title, 
							     chaveWorkspace,
							     -1, #workspaceId, #modificado
							     registeredEntity[0] ] )
			
				print("Workspace %s foi registrado corretamente" %self.reqWorAtt.workspace_title)			
			 	
	    		        #print("Dictionary de workspaces: %s" %workspaceRegisterDictionary)
				print("List de workspaces: %s" %workspaceRegisterList)		

				print("Termino do create...")

				print("Comeco do registro das regras de encaminhamento WC")				
				
				#adiciona regras de encaminhamento na estrutura de dados apenas
				self.addForwardingRules(self.reqWorAtt.entity_title, workspaceId, REDE_FISICA_ATUAL)
				
				print("Fim do registro das regras de encaminhamento WC")
										
				if(self.reqWorCre.attach_too) :											
					print("Atachando workspace no SBBWorkspaceManager...")
					(createStatus, wIdT) = self.workspaceAttach()	#so para retornar o valor wIdT nao sera usado (temporario)
				else :
					createStatus = dts_pb2.ControlResponse.SUCCESS  		  
		  
		return (createStatus, workspaceId)

		#except :

		#	print("Erro inesperado ao registrar entidade %s %s" %(self.reqEntReg.title,sys.exc_info()))
		#	return dts_pb2.ControlResponse.FAILURE


	def workspaceAttach(self):
		#try :

		attachStatus = dts_pb2.ControlResponse.SUCCESS
		
		registeredEntity = AttributeSearch(dictionaryRegisterEntity, self.reqWorAtt.entity_title, 1)

		if -1 == registeredEntity[0] :

			print("ERRO! Entidade %s nao foi registrada anteriormente" %self.reqWorAtt.entity_title)
			attachStatus = dts_pb2.ControlResponse.FAILURE

		else :

			print("Entidade retornada ", registeredEntity)

		  #registeredWorkspace = AttributeSearch(workspaceRegisterDictionary, self.reqWorAtt.workspace_title, 1)

		registeredWorkspace = buscaTuplaInList(workspaceRegisterList, 
						       [self.reqWorAtt.workspace_title], 
						       [1], 
						       1)
		  
		  #if(-1 != registeredWorkspace[0]) :
		  
		workspaceId = registeredWorkspace[0]
		  
		if(-1 == registeredWorkspace[0]) :

			print("ERRO! Workspace %s nao foi registrado anteriormente" %self.reqWorAtt.workspace_title)
			attachStatus = dts_pb2.ControlResponse.FAILURE

		else:
		
			print("Workspace retornado: ", registeredWorkspace)

		registeredWorkspaceEntity = buscaTuplaInList(workspaceEntityAttachList, 
							     [registeredWorkspace[0], registeredEntity[0]], 
						             [1, 2], #modificado
							     2)

		if registeredWorkspaceEntity[0] != -1 :

			print("ERRO! Attach do workspace %s e entidade %s ja foi registrado anteriormente" %(self.reqWorAtt.workspace_title, self.reqWorAtt.entity_title))
	
			attachStatus = dts_pb2.ControlResponse.FAILURE

		else:

			print("Registro workspace entidade retornado: ", registeredWorkspaceEntity)

						  
		if attachStatus == dts_pb2.ControlResponse.SUCCESS :

			workspaceEntityAttachList.append((int(len(workspaceEntityAttachList)+1), registeredWorkspace[0], registeredEntity[0]))
			
			print("Entidade %s foi attachada corretamente no workspace %s" %(self.reqWorAtt.entity_title, self.reqWorAtt.workspace_title ))

			print("Comeco do registro das regras de encaminhamento WA")				
			#parei aqui 
			self.addForwardingRules(self.reqWorAtt.entity_title, workspaceId, REDE_FISICA_ATUAL)				          

			print("Fim do registro das regras de encaminhamento WA")			

		print("Lista de attachs: %s" %workspaceEntityAttachList)			  
		  
		return (attachStatus, workspaceId)

		#except :

		#	print("Erro inesperado ao registrar entidade %s %s" %(self.reqEntReg.title,sys.exc_info()))
		#	return dts_pb2.ControlResponse.FAILURE
			
			

	#def __del__(self):
	#	if self.registered:
	#		self.unregister()
	#	self.socket.close()
			
	#def unregister(self):
	#	msg = etcp_pb2.EntityUnregister()
	#	msg.title = self.title
	#	res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_ENTITY_UNREGISTER)
	#	if res.status != dts_pb2.ControlResponse.SUCCESS:
	#		raise DTSException("Failed to unregister entity.")
	#	self.registered = False
















