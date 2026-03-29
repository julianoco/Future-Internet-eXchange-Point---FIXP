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

def responseSendD(sock, ethernetHeader, reqObj, status):
	
	sendAddr = "\xff\xff\xff\xff\xff\xff" + ethernetHeader[0:6]

	print("sendAddr: %s" %sendAddr)		

	respObj = dts_pb2.ControlResponse()
	respObj.status = status
	respObj.request_id = reqObj.id
	respObj.srcTitle = "DTSA"

	respObjSer = respObj.SerializeToString()
		
	print("Objeto de resposta serial: %s", respObjSer)
				
	sendRet = sock.send(sendAddr, struct.pack("<H", len(respObjSer)), respObjSer)
	
	return sendRet

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
		#print("Byte seq: ", byte_seq)
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

		print("sendAddr: %s" %sendAddr)		

		respObj = dts_pb2.ControlResponse()
		respObj.status = status
		respObj.request_id = reqObj.id
		respObj.srcTitle = "DTSA"

		respObjSer = respObj.SerializeToString()
		
		print("Objeto de resposta serial: %s", respObjSer)
				
		sendRet = self.sock.sendM(sendAddr, struct.pack("<H", len(respObjSer)), respObjSer)
	
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
											
						entRegObj = SBBEntityRegister(reqEntReg)
						status = entRegObj.entityRegister()

						print("Status retornado %d" %status)
						
						#if self.responseSend(ethernetHeader, reqObj, status) == -1 :
						if responseSendD(self.sock, ethernetHeader, reqObj, status) == -1 :
							print("Erro do envio da primitiva de resposta")					
							exit(1)
												
						print("Termino de registro")

						reqSea = True
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

class SBBEntityRegister(object):

	dictionaryRegisterEntity = dict()

	def __init__(self, reqEntReg):
		self.reqEntReg = reqEntReg

	def entityRegister(self):
		#try :

		  if(self.reqEntReg.title in self.dictionaryRegisterEntity) :

		  	print("ERRO! Entidade %s ja foi registrada anteriormente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.FAILURE

		  else :
			
			SBBEntityRegister.dictionaryRegisterEntity[int(len(self.dictionaryRegisterEntity)+1)] = self.reqEntReg.title
			
			print("Entidade %s foi registrada corretamente" %self.reqEntReg.title)
			registerStatus = dts_pb2.ControlResponse.SUCCESS

		  print("Dictionary de entidades: %s" %SBBEntityRegister.dictionaryRegisterEntity)	
		  
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
















