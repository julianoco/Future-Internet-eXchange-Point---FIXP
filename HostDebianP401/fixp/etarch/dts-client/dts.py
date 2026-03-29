from protocol import dts_pb2, etcp_pb2, dtscp_pb2
from dts_wire import buffer_splitter

import itertools
import hashlib

import socket
import struct
import fcntl

#raw socket em python 2.7
#https://docs.python.org/2/library/socket.html

#Returns mac addr for given interface
def getHwAddr(ifname) :
	#abre um novo socket som parametro AF_INET, familia IPV4 e o tipo de socket e SOCK_DGRAM
	#geralmente utilizado por datagramas por nao ter conexao.Voce envia um datagrama, recebe
	#uma resposta e a comumicacao entre as duas entidades termina, porque nao e uma 
	#comunicacao que envolve conexao. Para que ele esta abrindo um socket se ja ha
	#um raw socket aberto. Esta abrindo para obter o valor do mac da interface
	#por meio da utilizacao da funcao ioctl, que recebe o identificador do descritor de 
	#arquivo, no caso do socket, s.fileno(), depois passa o comando, no caso 0x8927
	#significa obter a interface de rede, e passas no terceiro parametro o valor da 
	#interface. Ele esta pegando de volta 256 bytes que como podera ser visto tera
	#algumas informacoes tais como a interface, essa eu ja tenho, traz tambem um 0x0001
	#que e um valor que eu nao sei o que e e traz o endereco mac que ja tenho
	#ou ja teria com a funcao getsockname que vai trazer algumas informacoes dependo
	#da familia de protocolo do socket, tais como endereco mac e nome da interface.
	#E importante salientar que pack vai devolver o tamanho que tiver um dos parametros
	#vai ter que olhar a descricao de pack, no caso ali acho que ele devolvera uma resposta
	#de 256 bytes	
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	
	
	#ioctl. executa instrucao do so, 0x8927 obter endereco de hardware
	#fileno. passa identificador do s
		
 	print("ifname: " + ifname + ".")
	print("ifname15: " + ifname[:15] + ".")
	print("struct.pack: ", struct.pack('256s', ifname[:15]))	

	#0x8927. obter mac da interface
	#struct.pack. passa em bytes para a funcao ioctl a informacao da interface
	#s.fileno retorna um descritor de arquivo(identificador do socket), um smaal int
	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
	print("info: ", info)	
	print("Na linha abaixo o pack: )")
 	print(struct.pack('256s', ifname[:15]))
	print("len(info", len(info))
	print("len(info2", len("eth0\x00\x00\x00"))
	#A resposta de fcntl.ioctl e grande (256 bytes) e aqui em baixo ele vai pegar
	#apenas um pedaco dessa resposta que equivale ao endereco mac da interface da maquina
	print("len(info", info[18:24])		
	return info[18:24]

#estou herdando de socket.socket
class DTSSocket(socket.socket):
	def __init__(self, iface):
		# Ethertype of MEHAR
		ETH_MEHAR = 0x0880

		# Creates a MEHAR socket
		# cria um socket passando AF_PACKET
		# Repersenta uma interface de baixo nivel cujos pacotes sao
		# representados pela tupla (ifname, proto, pktype)
                # ifname -> nome do dispositivo
		# proto -> numero do protocolo da Ethernet
                # pktype -> tipo de pacote
		#olhar em https://docs.python.org/3/library/socket.html#socket.SOCK_RAW
                
		socket.socket.__init__(self, socket.AF_PACKET,
				       socket.SOCK_RAW, ETH_MEHAR);

		# Binds to one specific interface, while nobody cares to define
		# a substitute to local IP route table. Of course, an efficient
		# global routing algorithm is of minor importance when thinking
		# something to replace TCP/IP.
		# vincula  a interface e o numero do mehar (acho que como porta)
		# para criar a porta de origem desse servidor que e o dts-client
		# parece que criando o bind dessa forma sera checado nessa porta
		# se o valor recebido o ethertype passado		
		self.bind((iface, ETH_MEHAR))
		# Set promiscuous mode...

		# Kernel constants

		#JULIANO: ioctl faz chamadas de sistema utilizando para isso um descritor de
		#arquivos. um descritor de arquivos e um objeto capaz de controlar arquivos
                #fileno() 

		#faz uma chamada de sistema via descritor de arquivo
                #fileno() pega o identificador do descritor de arquivo subjacente (porque existe??)
                #quando foi criado? hoje eu nao sei responder a essa pergunta

		#abaixo uma constante do kernel do linux
		#cujo comando significa: recupera o indice de interface de rede
		#https://manpages.debian.org/jessie/manpages-pt/netdevice.7.pt.html
		#ABAIXO TEM OS CODIGOS QUE ESSAS CONSTANTES TEM QUE TER
		#https://sites.uclouvain.be/SystInfo/usr/include/bits/ioctls.h.html
		SIOGIFINDEX = 0x8933
		SOL_PACKET = 263
		PACKET_ADD_MEMBERSHIP = 1
		PACKET_MR_PROMISC = 1

		# Find out device index, would be easier in Python 3 that has
		# socket.if_nametoindex() function...
		ifr = iface + "\0"*(20 - len(iface))
		
		#print("ifr: " + ifr)
		#print("len(ifr): " + str(len(ifr)))		
	
		#faz uma chamada de sistema passando o identificador do descritor de 			#arquivo 			subjacente -> nao sei como se conseguiu esse identificador
		#passao o comando atraves da constante SIOCGIFINDEX -> LA EM CIMA
		#a constante esta escrito errado, e passa o nome da interface
		#com comprimento de 20 bytes. De certo, lendo a descricao
		#se quer um retorno de 20 bytes caso o comando de certo
		#self.fileno() deve ser um identificador de descritor de arquivo
		#fornecido pelo linux
		#print("fileno: " + str(self.fileno()))
		#fileno() esta sendo herdado de socket.socket

		#Na computaCAOo, ioctl (uma abreviacao de controle de entrada/saida) e uma chamada 			#de sistema para operacoes de entrada/saida especificas do dispositivo e outras 		#operacoes que nao podem ser expressas por chamadas de sistema regulares. Leva um 			#parametro especificando um codigo de solicitacao; o efeito de uma chamada depende 			#completamente do codigo de solicitacao (segundo parametro, request).
         
		r = fcntl.ioctl(self.fileno(), SIOGIFINDEX, ifr)		
		
		#o parametro ifr tem 20 bytes de tamanho, entao vai ser devolvido
		#pela funcao ioctl 20 bytes de tamanho, deve ser por isso que o autor
		#original desse chat aumento em 20 vezes o tamanho da iface

		#Pelo que entendi, o ioctl coloca o args em buffer e caso de tudo certo devolve
                #esse mesmo valor para r. Por isso ele devolveu o eth0.
				
		print("\n*******Dados gerados por DTSSocket")
		print("ifr: " + ifr)
		print(r)
		print('r(len): ' + str(len(r)))	
		#https://docs.python.org/3/library/struct.html
		#pelo que tudo indica o r, retorno de ioctl esta vindo empacotado pelo pack
		#quando voce descompacta com 20s voce ve 
		#('eth0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00',)
		#quando voce descompacta com 16si voce ve
		#('eth0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 2)
		#esta retornando uma tupla, o pack retorna uma tupla, pelo menos esta retornando
		#primeiro elemento da tupla e o nome da interface
		#segundo elemento da tupla e o indice, parece ser o indice da interface
	        print(struct.unpack("20s",r))
		print(struct.unpack("16sI",r))
		ifidx = struct.unpack("16sI", r)[1]
		print('ifidx: ' + str(ifidx))		
		print("*******Fim de DTSSocket\n")

		# Request promiscuous mode
		#parece que para solicitar modo promiscuo, uma das informacoes que tem que
		#enviar e o indice da interface
		#I inteiro H short 8s sao oito caracteres
		packet_mreq = struct.pack("IHH8s", ifidx, PACKET_MR_PROMISC,
					  6, "\0"*6)
		#print(packet_mreq)

		#configura o socktet para modo promiscuo
		#https://docs.python.org/3/library/socket.html
		#https://manpages.debian.org/bullseye/manpages-dev/setsockopt.2.en.html	
		self.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)

		# For generating ids:
		itertools.count();
		self.id_counter = itertools.count()
		#print("id_counter: " + str(self.id_counter))		

	def send(self, addr, *msg_bufs):
		# TODO: validate address size...

		# Ethertype of MEHAR

		print("msg_bufs: ", msg_bufs)

		#chatprint("executando o send")
		#ethertype 0880 e o ethertype das primitivas etarch
		ethertype = "\x08\x80"
		
		#cria uma lista ou cadeia ou tupla e coloca todas as informacoes
		#une as informacoes da primeira e segunda tupla
		byte_seq = itertools.chain((addr, ethertype), msg_bufs)

		#a linha abaixo da problemas se for executada, da problema
		#no envio, no send
		#print "Sequencia de bytes: " + str(list(byte_seq))
		#print ("Sequencia de bytes 2: ", ''.join(byte_seq))
		#abaixo o que e impresso na linha acima
		#('Sequencia de bytes 2: ', "DTS\x00\x00\x00\x08\x00'\xc9\xbe'\x08\x80\x04\x00\x08\x00\x10\x00\x04\x00\n\x02e1")
		
		#chatprint("Byte seq: ", byte_seq)
		#chatprint('Byte seq: ', ''.join(byte_seq))
		#chatfor item in byte_seq:
		#chat	print("item ", item, "\n")
		#for item in byte_seq :
		#  print(str(item))

		#print("Abaixo o sequencia de bytes que sera enviado")		
		#cuidado com a linha abaixo, a sua impressao altera algo que eu nao sei o que e
		#e o send logo apos da problema.
		#print list(byte_seq)		
			
		#o join tira as informacoes da tupla ou lista de byte_seq e coloca tudo junto
		#como uma so string separada apenas por '', ou seja, nao esta separada por nada
		#e envia
		#os parametros passados sao o self(que e o DTSSOCKET que herda socket.socket
		#e os bytes que serao enviados
		#o que ele retorna? retorna o numero de bytes enviados
		#se retornar -1 e porque deu erro		
		return socket.socket.send(self, ''.join(byte_seq))

	def send_all(self, addr, msg_buffer):
		sent = 0
		while sent < len(msg_buffer):
			sent += self.send(addr, msg_buffer[sent:])

	def recv_filter(self, addr, filterP = 0):
		while True:
			# TODO: get interface's MTU instead of hardcoding
			#chatprint("Comecando o receiver: ")
			#O programa para abaixo e espera uma resposta
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
			elif filterP == 1 : #data macs distintos e mesmo workspace
					    #esse teste e importante para que o enviador nao receba sua propria mensagem
                               	#filterP == 1 quer dizer que e pacote de dados
			        #abaixo quer dizer macs_scr nao sao os mesmos mas os macs de destino sao
				#ou seja, entidades maquinas diferentes e mesmo workspace
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
	#header e o control primitive que vai existir em todas as primitivas Etarch
	#ou seja, que e comum em todas as primitivas java
	#o Flavio chama esse pedaco de objeto de control primitive na pagina 158
	header = dts_pb2.ControlRequest()
	header.type = msg_type
	#toda vez que for mandar uma mensagem vai colocar um id diferente
	#primeira vez que enviar a mensagem manda 0, a segunda vez manda 1,
	#e assim por diante
	header.id = sock.id_counter.next()	
	#header.dstTitle = "Juliano"
	print "***** produzido pela funcao call_dts"
	print("header.id: " + str(header.id))
	#exit(1)
	# The chosen generic address to DTS
	# MONTAGEM DO HEADER DO PACOTE: DTS\0\0\0+INTERFACE
	#retorna interface, protocolo, mac
	#exemplo 08:00:27:ce:fa:93, aparece \x08\x00'\xce\xfa\x93
	print("sock.getsockname() ", sock.getsockname(), "\n")
	#exit(1)
	#nao precisava chamar getHwAddr porque o valor do mac ja esta
	#edm getsockname[4]
	addrSend = "DTS\x00\x00\x00" + getHwAddr(sock.getsockname()[0])
	print("getHwAddr() ", getHwAddr(sock.getsockname()[0]), "\n")	
	print("addrSend: ", addrSend, "\n")
	print("addrSend1: ", addrSend[4:], "\n")	
	print("addrSend2: ", addrSend[:6], "\n")
        
	#exit(1)

	#invert
	#addRcv recebe primeiro o valor do mac e depois o valor DTS\x00\x00\x00
	addrRcv = addrSend[6:] + addrSend[:6]
	print("addrRcv: ", addrRcv, "\n")		
	#MONTAGEM DOS DADOS QUE VAO NO PACOTE
        print("header: ", header)
	
	#SerializeToString(): serializa a mensagem e a retorna como uma string. Observe que os bytes sao binarios, 	   #nao texto; usamos apenas o tipo str como um container conveniente.
	header_serial = header.SerializeToString()
	print("head serializado: ", header_serial)
	msg_serial = msg_obj.SerializeToString()
	print("msg: ", msg_obj)
	print("msg serializado: ", msg_serial)
	print("*********")

	print("\n*********Iniciando o send do call_dts")
	print("Addr Send: ", addrSend)
	#esse pack formata o comprimento de header_serial para litle indian e o devolve em bytes
	print("comprimento do header serial: " + str(len(header_serial)))
	print("comprimento do msg serial: " + str(len(msg_serial)))
	print("struct 01: ", struct.pack("<H", len(header_serial)))
	print("struct 03: ", struct.pack("<H", len(msg_serial)))

	#https://www.youtube.com/watch?v=PGAtCGqt06U
	#struct.pack 'iif', cada um para um parametro 
	#parametros: https://docs.python.org/2/library/struct.html#format-characters
	#calcsize(i). retorna o tamanho de bytes do formato
	#packet_data = pack('iif', 6, 19, 4.73)
	#unpack('iif', packet_data)
	
	#print("Testando inicio de envio")
	
	#o send abaixo nao e a funcao send do socket.socket, e a funcao send da 
	#classe DTSSocket, que extende socket.socket
	#passa como parametro o addrSend que e o DTS\x00\x00\x00 e o mac da maquina
        #estou passando a mensagem, que o send chamou de buffer mensagem
	#todos os parametros abaixo vao se unir posteriormente para que a gente consiga
	#enviar a mensagem
	#parei aqui.

	sent = sock.send(addrSend,
			 struct.pack("<H", len(header_serial)), header_serial,
			 struct.pack("<H", len(msg_serial)), msg_serial)
	print("Testando fim de envio")
	print("*****Terminando o send")		

	if sent != 0:
		# TODO: deal with the case the message to DTS doesn't
		# fit the ethernet frame
		pass

	# Wait for response
	# parei aqui - Juliano
	resp_obj = dts_pb2.ControlResponse()
	found_resp = False
	print("********Inicializando a reposta do EntityRegister")
	while not found_resp:
		print("passou2!")
		#nesse momento ele para e vai esperar a resposta
		data = sock.recv_filter(addrRcv)
		print("passou3!")		
		for msg_buffer in buffer_splitter(data):
			resp_obj.ParseFromString(msg_buffer)

			print("id do objeto recebido: ", resp_obj.request_id)
			print("header.id: ", header.id)
			print("status do objeto recebido", resp_obj.status)
			print("Source do objeto recebibo", resp_obj.srcTitle)

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
		#coloca como hash_title
		self.hash_title = hashlib.sha256(title).digest()[:6] + getHwAddr(iface)
		#chatprint("hash_title: {}", self.hash_title)
		self.socket = DTSSocket(iface)
		self.attached_entity = None
		self.created = False

	def __del__(self):		
		self.socket.close()
	'''
		if self.attached_entity:
			self.detach()
		if self.created:
			self.delete_on_dts()
	'''
		
	

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
	#iface e a interface de rede
	#title e o titulo da entidade
	#register_now ainda nao sei
	#register_now e uma variavel booleana para dizer
	#para registrar entidade no momento da chamada
	#do construtor
	def __init__(self, iface, title, register_now=False):
		self.iface = iface
		self.title = title
		self.registered = False		
		#chama o construtor DTSSocket e passa a interface
		self.socket = DTSSocket(iface)
		if register_now:
			self.register()

	def __del__(self):		
		self.socket.close()
	'''
		if self.registered:
			self.unregister()
        '''
						
	def register(self):
		#msg e um objeto da classe EntityRegister configurada no protobuf
		#a partir dai voce pode pegar os atributos que sao fortemente tipados
		msg = etcp_pb2.EntityRegister()
		msg.title = self.title
		#passa o socket, a mensagem do objeto, e o tipo de mensagem
		#a msg vai ser passada por primitiva, pois cada primitiva tem o objeto
		#diferente da outra, porem la em call_dts ele cria uma primitiva que e padrao
		#para todas, o que a tese do Flavio chama de control primitive no desenho da
		#pagina 158. msg aqui equivale ao que o flavio chama de specific to each primitive
		#ou primitive type (que esta nesse mesmo desenho)
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
