from protocol import dts_pb2, etcp_pb2, dtscp_pb2
from dts_wire import buffer_splitter

import itertools
import hashlib

import socket
import struct
import fcntl
import sys

#Returns mac addr for given interface
def getHwAddr(ifname):
	print("teste")
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	
	#ioctl. executa instrucao do so, 0x8927 obter endereco de hardware
	#fileno. passa identificador do s
	#
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
	def __init__(self, iface):
		# Ethertype of MEHAR

		print("iface teste ", iface);

		ETH_MEHAR = 0x0880

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

	def send(self, addr, *msg_bufs):
		# TODO: validate address size...

		# Ethertype of MEHAR

		print("executando o send")
		ethertype = "\x08\x80"

		byte_seq = itertools.chain((addr, ethertype), msg_bufs)
		print("Byte seq: ", byte_seq)
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
		while True:
			# TODO: get interface's MTU instead of hardcoding
			print("comeco do recebimento")
			resp = self.recv(1518)
			print("fim do recebimento", resp)
			print("Resp 0:6", resp[0:6])
			print("Resp 12-14", resp[12:14])
			print("Resp 0-14", resp[0:14])
			print("Resp 14:", resp[14:])
			#return resp
			#print ''.join( [ "%02X " % ord( x ) for x in resp[:12]] ).strip()
			if (resp[0:6] == "DTS\x00\x00\x00" and resp[12:14] == "\x08\x80"):
				return (resp[0:14], resp[14:])
				# There is no need to check ethertype because
				# the socket interface will do it for us.
			#return resp[14:] # Strip ETH header/footer

class SBBNEConnector(object):

	def __init__(self, iface):
		self.iface = iface
		self.sock = DTSSocket(iface)
		self.primitiveParser()
	'''	
	def __del__(self):
		if self.registered:
			self.unregister()
		self.socket.close()
	'''

	def responseSend(self, ethernetHeader, reqObj, status):
	
		sendAddr = "\xff\xff\xff\xff\xff\xff" + ethernetHeader[0:6]

		print("sendAddr: ", sendAddr)		

		respObj = dts_pb2.ControlResponse()
		respObj.status = status
		respObj.request_id = reqObj.id
		respObj.srcTitle = "DTSA"

		respObjSer = respObj.SerializeToString()
		
		print("Objeto de resposta serial: %s", respObjSer)
				
		sendRet = self.sock.send(sendAddr, struct.pack("<H", len(respObjSer)), respObjSer)
	
		return sendRet
							
			
	def primitiveParser(self):

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

					reqObj.ParseFromString(msg_buffer)
					print("Type: %s" % reqObj.type)
					print("Id: %d" % reqObj.id)
					print("Title: %s"  % reqObj.dstTitle)
				
				elif cont == 1 :
 
					if reqObj.type == dts_pb2.ControlRequest.ETCP_ENTITY_REGISTER :
	
						print("Registrando entidade no SBB Entity Manager...")
								
						reqEntReg = etcp_pb2.EntityRegister()
						reqEntReg.ParseFromString(msg_buffer)
						
						print("Titulo: %s" %reqEntReg.title)
											
						entRegObj = SBBEntityManager(reqEntReg)
						status = entRegObj.entityRegister()

						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
						if self.responseSend(ethernetHeader, reqObj, status) <= 0 :
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
	
						print("Criando/Atachando workspace no SBB Entity Manager...")
								
						reqWorAttCre = etcp_pb2.WorkspaceCreate()
						reqWorAttCre.ParseFromString(msg_buffer)

					        reqWorAtt = etcp_pb2.WorkspaceAttach()
		        			reqWorAtt.workspace_title = reqWorAttCre.workspace_title
					        reqWorAtt.entity_title = reqWorAttCre.entity_title

						
						print("Worskpace: %s" %reqWorAttCre.workspace_title)
						print("Entidade: %s" %reqWorAttCre.entity_title)
						print("Attach_too: %s" %reqWorAttCre.attach_too)
											
						worAttCreObj = SBBWorkspaceManager(reqWorAtt, reqWorAttCre)
						status = worAttCreObj.workspaceCreate(entRegObj.dictionaryRegisterEntity)

						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
						if self.responseSend(ethernetHeader, reqObj, status) <= 0 :
							print("Erro do envio da primitiva de resposta")					
							exit(1)
												
						print("Termino de create/attach")

						reqSea = True
						break					

						#Montar uma funcao que monta ControlResponse.. todas as SBBs irao
						#utilizar essafuncao... seria legal criar uma biblioteca de 
						#funcoes uteis que serao compartilhadas
						#a classe vai montar 


					elif reqObj.type == dts_pb2.ControlRequest.ETCP_WORKSPACE_ATTACH :
	
						print("Atachando workspace no SBB Entity Manager...")
								
						reqWorAtt = etcp_pb2.WorkspaceAttach()
						reqWorAtt.ParseFromString(msg_buffer)
						
						print("Worskpace: %s" %reqWorAtt.workspace_title)
						print("Entidade: %s" %reqWorAtt.entity_title)
											
						worAttObj = SBBWorkspaceManager(reqWorAtt, etcp_pb2.WorkspaceCreate())
						status = worAttObj.workspaceAttach(entRegObj.dictionaryRegisterEntity)								   

						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
						if self.responseSend(ethernetHeader, reqObj, status) <= 0 :
							print("Erro do envio da primitiva de resposta")					
							exit(1)
												
						print("Termino de attach")

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
		SBBEntityManager.dictionaryRegisterEntity = dict()

 	@property
	def dictionaryRegisterEntity(self):
		return SBBEntityManager.dictionaryRegisterEntity

	def entityRegister(self):
		#try :

		  if(self.reqEntReg.title in SBBEntityManager.dictionaryRegisterEntity.values()) :

		  	print("ERRO! Entidade %s ja foi registrada anteriormente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.FAILURE

		  else :
			
			SBBEntityManager.dictionaryRegisterEntity[int(len(self.dictionaryRegisterEntity)+1)] = self.reqEntReg.title
			
			print("Entidade %s foi registrada corretamente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.SUCCESS

		  print("Dictionary de entidades: %s" %SBBEntityManager.dictionaryRegisterEntity)	
		  
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

#retorna conteudo achado
def AttributeSearch(searchDictionary, contentP, columnNumberP):

	for search in searchDictionary.items() :
			
		if search[columnNumberP] == contentP :

			return search

	return (-1,)

class SBBWorkspaceManager(object):	

	def __init__(self, reqWorAtt, reqWorCre):
		self.reqWorAtt = reqWorAtt
		self.reqWorCre = reqWorCre

		#0. Identificador de registro do workspace 
		#1. Titulo do workspace  
		#2. Identificador da entidade
		SBBWorkspaceManager.worskpaceRegisterDictionary = dict()

		#0. Identificador do workspace
		#1. Identificador da entidade attachada
		SBBWorkspaceManager.workspaceEntityAttachList = list()

	def workspaceCreate(self, dictionaryRegisterEntity):
		#try :

		  if(self.reqWorAtt.workspace_title in self.worskpaceRegisterDictionary.values()) :

		  	print("ERRO! Worspace %s ja foi criado anteriormente" %self.reqWorAtt.workspace_title)
			createStatus = dts_pb2.ControlResponse.FAILURE

		  else :
			
			SBBWorkspaceManager.worskpaceRegisterDictionary[int(len(self.worskpaceRegisterDictionary)+1)] = self.reqWorAtt.workspace_title
			
			print("Workspace %s foi registrado corretamente" %self.reqWorAtt.workspace_title)			
		 	
    		        print("Dictionary de workspaces: %s" %SBBWorkspaceManager.worskpaceRegisterDictionary)	

		        print("Termino do create...")
		        			
			if(self.reqWorCre.attach_too) :											
				print("Atachando workspace no SBB Entity Manager...")
			        createStatus = self.workspaceAttach(dictionaryRegisterEntity)								   		  
		  
		  return createStatus

		#except :

		#	print("Erro inesperado ao registrar entidade %s %s" %(self.reqEntReg.title,sys.exc_info()))
		#	return dts_pb2.ControlResponse.FAILURE


	def workspaceAttach(self, dictionaryRegisterEntity):
		#try :

		  attachStatus = dts_pb2.ControlResponse.SUCCESS

		  registeredEntity = AttributeSearch(dictionaryRegisterEntity, self.reqWorAtt.entity_title, 1)

		  if -1 == registeredEntity[0] :

		  	print("ERRO! Entidade %s ja foi registrada anteriormente" %self.reqWorAtt.entity_title)
			attachStatus = dts_pb2.ControlResponse.FAILURE

		  else :

			print("Entidade retornada ", registeredEntity)

		  registeredWorkspace = AttributeSearch(self.worskpaceRegisterDictionary, self.reqWorAtt.workspace_title, 1)
		  
		  if(-1 == registeredWorkspace[0]) :

		  	print("ERRO! Workspace %s nao foi registrado anteriormente" %self.reqWorAtt.workspace_title)
			attachStatus = dts_pb2.ControlResponse.FAILURE

		  else:
		
			print("Workspace retornado: ", registeredWorkspace)

		  registeredWorkspaceEntity = buscaTuplaInList(SBBWorkspaceManager.workspaceEntityAttachList, 
							       [registeredWorkspace[0], registeredEntity[0]], 
						               [0, 1], 
							       2)

  		  if registeredWorkspaceEntity[0] != -1 :

		  	print("ERRO! Attach do workspace %s e entidade %s ja foi registrado anteriormente" %(self.reqWorAtt.workspace_title, self.reqWorAtt.entity_title))
	
			attachStatus = dts_pb2.ControlResponse.FAILURE

		  else:

			print("Registro workspace entidade retornado: ", registeredWorkspaceEntity)

						  
  		  if attachStatus == dts_pb2.ControlResponse.SUCCESS :

		  	SBBWorkspaceManager.workspaceEntityAttachList.append((int(len(SBBWorkspaceManager.workspaceEntityAttachList)+1), registeredWorkspace[0], registeredEntity[0]))						     
			
			print("Entidade %s foi attachada corretamente no workspace %s" %(self.reqWorAtt.entity_title, self.reqWorAtt.workspace_title ))

		  print("Dictionary de attachs: %s" %SBBWorkspaceManager.workspaceEntityAttachList)	
		  
		  return attachStatus

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
















