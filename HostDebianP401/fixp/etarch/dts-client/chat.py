#!/usr/bin/python2.7

import sys
import itertools
import gevent
import gevent.select
from subprocess import call
from gevent import monkey
monkey.patch_socket()
import hashlib
import dts
import time

def main():
    '''
    abaixo fiz somente para testes
    resp = hashlib.sha256(sys.argv[3]).digest()[:6]

    print("*********dados do hashs")
    print("comprimento do hash completo: {}", len(hashlib.sha256(sys.argv[3]).digest()))
    print("hash completo: {}", hashlib.sha256(sys.argv[3]).digest())
    print("hash reduzido: {}", resp)
    print("comprimento do hash reduzido: {}", len(resp))
    print("*********dados dos hashs")
    exit(1)
    '''
    
    '''
	sys.argv[0] = chat.py
	sys.argv[1] = valor da interface
        sys.argv[2] = valor do titulo da entidade
        sys.argv[3] = valor do titulo do workspace        
        
    '''
	
    #inicio_modificacao
    dataInicio = time.time()
    #fim_modificacao

    #Se os parametros nao foram passados corretamente
    #precisa de tres parametros, 1,2,3, porem sys.argv tambem conta o nome do programa
    if len(sys.argv) < 4:
        print "\n*****Error:\n\tUsage{} <interface> <entity_title> <workspace_title> <interval in ms>\n*****\n".format(" " +
            sys.argv[0])

        #print sys.argv[0]
        #print sys.argv[1]
        #print sys.argv[2]
	#print len(sys.argv)
        sys.exit(1)

    else : #se os parametros foram passados corretamente, escreve o log abaixo

        print "\n********Parametros passados corretamente"
        print "Nome do programa........................: " + sys.argv[0]
	print "Primeiro parametro (interface de rede)..: " + sys.argv[1]
	print "Segundo parametro (titulo da entidade)..: " + sys.argv[2]
	print "Terceiro parametro (titulo do workspace): " + sys.argv[3]
	print "Comprimento da entrada..................: " ,len(sys.argv)
	print "********Fim dos parametros\n"

    
    #sha256   -> algoritmo de hash (use sha256() to create a SHA-256 hash object)
    #digest() -> retorna um hash de 32 bytes, uma string que e um byte (tamanho 32)
    #hexdigest() -> igual ao de cima, mas retorna 64 bits pois cada dois bis e  um 
    #numero hexadecimal que representa 32 bytes
    print("*********dados dos hashs 01")
    print("hash completo: {}", hashlib.sha256(sys.argv[3]).digest())    
    print("hash reduzido: {}", hashlib.sha256(sys.argv[3]).digest()[:6])
    print("*********Fim")

    #pega o nome da interface
    iface = sys.argv[1]
    # chama a classe Entity para enviar o entity register
    # passa como parametro para o construtor o titulo da entidade e um valor booleano     	
    e = dts.Entity(iface, sys.argv[2], True)
    print 'Entity "{}" registered.'.format(e.title)

    #gera um hash do titulo do workspace; apenas os primeiros 06 bytes
    resp = hashlib.sha256(sys.argv[3]).digest()[:6]

    print("*********dados do hashs")
    print("comprimento do hash completo: {}", len(hashlib.sha256(sys.argv[3]).digest()))
    print("hash completo: {}", hashlib.sha256(sys.argv[3]).digest())
    print("hash reduzido: {}", resp)
    print("comprimento do hash reduzido: {}", len(resp))
    print("*********dados dos hashs")
        	
    w = dts.Workspace(iface, sys.argv[3])
    # DADOS SENDO ENVADOS E RECEBIDOS
    try:
        w.attach(e)
        print 'Attached to workspace "{}".'.format(w.title)	
    except dts.DTSException:
        # Failed to attach, probably does not exists,
        # then try to create
	print 'Failed to attach, trying to create'
        w.create_on_dts(e)
        print 'Created workspace "{}" and attached to it.'.format(w.title)

    #inicio_modificacao
    dataFim = time.time()
    print("Inicio: " + str(dataInicio))
    print("Final: " + str(dataFim))
    print("Tempo de Controle Gasto: " + str(dataFim - dataInicio))

    #fim_modificacao

    #sys.exit(1)    

    #chatprint("Comeco do bate papo")

    def reader_loop():
        try:
            while True:
                msg = w.recv()
                sys.stdout.write(msg)
        except gevent.GreenletExit, KeyboardInterrupt:
            pass

    reader = gevent.spawn(reader_loop)

    # Receiver loop
    try:
        cont = 1
        while True:
            gevent.select.select([sys.stdin.fileno()], [], [])
            if len(sys.argv) == 5:
                from time import sleep
                sleep(float(sys.argv[4])/1000.)
                w.send(str(cont) + '\n')
                cont+=1
            else:
                msg = raw_input()
                try:
                    if msg[:13] == './videoserver':
                        import os
                        dire = os.getcwd()
                        os.system("ffmpeg -re -i {}/{} -f mpegts -vcodec mpeg4 -strict -2 -acodec ac3 -ac 2 -ab 128k -r 30 -b:v 2000k -threads 2 etcp:{}:{}".format(dire, msg.split()[1], ''.join( [ "%02x" % ord( x ) for x in resp[:12]]).strip(), iface))
                    elif msg[:13] == './videoclient':
                        import os
                        os.system("ffplay etcp:{}:{}".format(''.join( [ "%02x" % ord( x ) for x in resp[:12]] ).strip(), iface))
                    else:
                        w.send(msg + '\n')
                except:
                    print 'Incorrect input'
    except EOFError, KeyboardInterrupt:
        pass
    
    # User endeded session with EOF, stop receiving...
    reader.kill(block=True)

    # Done. The destructors will do the cleanup automatically for us.

print("****************************** Comeco do sistema")
print("__name__", __name__)
if __name__ == "__main__":
    main()

