import struct

#https://docs.python.org/2/library/struct.html
#https://docs.python.org/2/library/struct.html#struct-format-strings

# With the wire format of 2 bytes little-endian size preceeding each
# protobuff message, this iterator will return the correctly split message
# buffer.

def buffer_splitter(full_buffer):
	bcount = 0
	full_len = len(full_buffer)
	while bcount < full_len:
		#ele desempacota de 2 em 2 porque ele sabe que o primeiro dado
		#do raw e o comprimento de 2 bytes representado por <H
		#litle endian
		#msg_size e o tamanho que foi configurado para mensagem
		#apos o desempacotamento, qual o tamanho estava configurado no campo
		#no caso e o tamanho que o dado tem, porque foi o tamanho do dado
		#que foi empacotado em dts.py na aplicacao etarch
		#ele pega os dados olhando o comprimento de cada dado atraves de msg_size
		(msg_size,) = struct.unpack("<H", full_buffer[bcount:bcount+2])
		bcount += 2
		if(msg_size != 0) :
			yield full_buffer[bcount:bcount+msg_size]
			bcount += msg_size


'''
def buffer_splitter(full_buffer):
	bcount = 0
	full_len = len(full_buffer)
	while bcount < full_len:
		(msg_size,) = struct.unpack("<H", full_buffer[bcount:bcount+2])
		bcount += 2

		yield full_buffer[bcount:bcount+msg_size]
		bcount += msg_size
'''
