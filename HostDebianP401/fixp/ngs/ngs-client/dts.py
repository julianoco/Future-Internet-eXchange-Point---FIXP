from protocol import dts_pb2, etcp_pb2, dtscp_pb2
from dts_wire import buffer_splitter

import itertools
import hashlib

import socket
import struct
import fcntl

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
		ETH_MEHAR = 0x1235

		# Creates a MEHAR socket
		socket.socket.__init__(self, socket.AF_PACKET,
				       socket.SOCK_RAW, ETH_MEHAR);

		# Binds to one specific interface, while nobody cares to define
		# a substitute to local IP route table. Of course, an efficient
		# global routing algorithm is of minor importance when thinking
		# something to replace TCP/IP.
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

		#chatprint("executando o send")
		ethertype = "\x12\x35"

		byte_seq = itertools.chain((addr, ethertype), msg_bufs)
		#chatprint("Byte seq: ", byte_seq)
		#print('Byte seq: ', ''.join(byte_seq))
		return socket.socket.send(self, ''.join(byte_seq))

	def send_all(self, addr, msg_buffer):
		sent = 0
		while sent < len(msg_buffer):
			sent += self.send(addr, msg_buffer[sent:])

	def recv_filter(self, addr, filterP = 0):
		while True:
			# TODO: get interface's MTU instead of hardcoding
			#chatprint("Comecando o receiver: ")
			resp = self.recv(1518)	
			#chatprint("Acabando o receiver: ", resp)
			#print ''.join( [ "%02X " % ord( x ) for x in resp[:12]] ).strip()
			#chatprint("resp[6:12]", resp[6:12])
			#chatprint("addr[6:12]", addr[6:12])
			#chatprint("addr[:6]", addr[:6])
			#chatprint("resp[:6]", resp[:6])
			if filterP == 0 : #controle
    				if resp[6:12] == addr[6:12] : #or resp[6:12] == addr[:6]:
					# There is no need to check ethertype because
					# the socket interface will do it for us.
					return resp[14:] # Strip ETH header/footer
			elif filterP == 1 : #data
				if resp[6:12] != addr[6:12] and resp[:6] == addr[:6] : #or resp[6:12] == addr[:6]:
					# There is no need to check ethertype because
					# the socket interface will do it for us.
					return resp[14:] # Strip ETH header/footer
		
	def recvTeste(self):
		resp = self.recv(1518)	


# Send message to DTS and wait for response.
# This function will discard incoming messages it doesn't find relevant,
# making it *NOT* reentrant (it may discard the response of a concurrent call).
def call_dts(sock, msg_obj, msg_type):
	header = dts_pb2.ControlRequest()
	header.type = msg_type
	header.id = sock.id_counter.next()
	#header.dstTitle = "Juliano"

	# The chosen generic address to DTS
	# MONTAGEM DO HEADER DO PACOTE: DTS\0\0\0+INTERFACE
	print("sock.getsockname() ", sock.getsockname(), "\n")
	addrSend = "DTS\x00\x00\x00" + getHwAddr(sock.getsockname()[0])
	print("getHwAddr() ", getHwAddr(sock.getsockname()[0]), "\n")	
	print("addrSend: ", addrSend, "\n")
	print("addrSend1: ", addrSend[4:], "\n")	
	print("addrSend2: ", addrSend[:6], "\n")		

	#invert
	addrRcv = addrSend[6:] + addrSend[:6]
	print("addrRcv: ", addrRcv, "\n")		
	#MONTAGEM DOS DADOS QUE VAO NO PACOTE
        print("header: ", header)	
	header_serial = header.SerializeToString()
	print("head serializado: ", header_serial)
	msg_serial = msg_obj.SerializeToString()
	print("msg: ", msg_obj)
	print("msg serializado: ", msg_serial)

	print("Iniciando o send")
	print("Addr Send: ", addrSend)
	print("struct 01: ", struct.pack("<H", len(header_serial)))
	print("struct 03: ", struct.pack("<H", len(msg_serial)))

	 #https://www.youtube.com/watch?v=PGAtCGqt06U
	#struct.pack 'iif', cada um para um parametro 
	#parametros: https://docs.python.org/2/library/struct.html#format-characters
	#calcsize(i). retorna o tamanho de bytes do formato
	#packet_data = pack('iif', 6, 19, 4.73)
	#unpack('iif', packet_data)
	
	print("Testando inicio de envio")
	sent = sock.send(addrSend,
			 struct.pack("<H", len(header_serial)), header_serial,
			 struct.pack("<H", len(msg_serial)), msg_serial)
	print("Testando fim de envio")

	print("Terminando o send")

	if sent != 0:
		# TODO: deal with the case the message to DTS doesn't
		# fit the ethernet frame
		pass

	# Wait for response
	resp_obj = dts_pb2.ControlResponse()
	found_resp = False
	while not found_resp:
		data = sock.recv_filter(addrRcv)
		for msg_buffer in buffer_splitter(data):
			resp_obj.ParseFromString(msg_buffer)

			print("id do objeto recebido: ", resp_obj.request_id)
			print("header.id: ", header.id)
			print("status do objeto recebido", resp_obj.status)
			print("Source do objeto receibo", resp_obj.srcTitle)

			print resp_obj.request_id
			print header.id
			if resp_obj.request_id == header.id:
				found_resp = True
				break;
	return resp_obj

class DTSException(Exception):
	pass

class Workspace(object):
	def __init__(self, iface, title):
		self.title = title
		self.hash_title = hashlib.sha256(title).digest()[:6] + getHwAddr(iface)
		#chatprint("hash_title: {}", self.hash_title)
		self.socket = DTSSocket(iface)
		self.attached_entity = None
		self.created = False

	def __del__(self):
		if self.attached_entity:
			self.detach()
		if self.created:
			self.delete_on_dts()
		self.socket.close()

	def create_on_dts(self, auto_attach_to=None):
		msg = etcp_pb2.WorkspaceCreate()
		msg.workspace_title = self.title

		if auto_attach_to:
			msg.entity_title = auto_attach_to.title
			msg.attach_too = True

		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_WORKSPACE_CREATE)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Workspace creation failed.")

		self.created = True
		if auto_attach_to:
			self.attached_entity = auto_attach_to

	def delete_on_dts(self):
		msg = etcp_pb2.WorkspaceDelete()
		msg.title = self.title

		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_WORKSPACE_DELETE)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Workspace deletion failed.")

		self.created = False

	def attach(self, entity):
		msg = etcp_pb2.WorkspaceAttach()
		msg.workspace_title = self.title
		msg.entity_title = entity.title

		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_WORKSPACE_ATTACH)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Failed to attach to workspace.")

		self.attached_entity = entity

	def detach(self):
		msg = etcp_pb2.WorkspaceDetach()
		msg.workspace_title = self.title
		msg.entity_title = self.attached_entity.title

		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.ETCP_WORKSPACE_DETACH)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Failed to detach from workspace.")

		self.attached_entity = False

	def send(self, msg):
		self.socket.send_all(self.hash_title, msg)

	def recv(self):
		#chatprint("hash_title", self.hash_title)
		return self.socket.recv_filter(self.hash_title, 1)

class Entity(object):
	def __init__(self, iface, title, register_now=False):
		self.iface = iface
		self.title = title
		self.registered = False
		self.socket = DTSSocket(iface)
		if register_now:
			self.register()

	def __del__(self):
		if self.registered:
			self.unregister()
		self.socket.close()
			
	def register(self):
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
		self.registered = False

class DTSA(object):
	def __init__(self, iface, title):
		self.iface = iface
		self.title = title
		self.socket = DTSSocket(iface)
		self.registered = False
	
	def register(self):
		msg = dtscp_pb2.DTSARegister()
		msg.title = self.title
		res = call_dts(self.socket, msg, dts_pb2.ControlRequest.DTSCP_DTSA_REGISTER)
		if res.status != dts_pb2.ControlResponse.SUCCESS:
			raise DTSException("Failed to register DTSA.")
		self.registered = True
