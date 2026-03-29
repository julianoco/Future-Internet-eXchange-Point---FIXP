#!/usr/bin/python2.7

import sys
import itertools
import gevent
import gevent.select
from subprocess import call
from gevent import monkey
monkey.patch_socket()
import hashlib
#import dts

import os
import SBBNEConnector

def main():

    #acho que o i e o valor de os.lisdir('sys/class/net/')
    #ou seja, todos os diretorios    
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    print()
    print("****************************************Comeco do controller 01 - Etarch")
    print("ifaces: ", ifaces)
    ifaces.sort()
    print("ifaces ordenado: ", ifaces)
    #Logo apos ordena, isso quer dizer que o controlador ouvira apenas
    #a primeira interface, que sera a interface padrao das mensagens de controle
    iface = ifaces[0]
    print("Sniffing on %s" %iface)

    sbbNEConnector = SBBNEConnector.SBBNEConnector(iface)
	
if __name__ == "__main__":
    main()

