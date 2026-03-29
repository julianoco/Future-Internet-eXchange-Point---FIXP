#!/usr/bin/env python
import sys
import struct
import os
import socket
import json

def rule_handler():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', 8888))
    server.listen(1)

    print 'Rule Handler Client on port 8888'

    while 1:
        conn = server.accept()

        while 1:

            print 'data received'

            encoded_data = conn.recv(256)
            json_data = json.loads(encoded_data.decode())
            data = json_data.get("data")

            #TODO: get info from data and assembly a new rule
            
            #Send new rule to server to be added by P4 Runtime
            try:
                clientSocket = socket.socket(ocket.AF_INET, socket.SOCK_STREAM)
                result = clientSocket.connect(('192.168.231.101', 9999))

                #TODO: set fields with correct received data
                rule = "table_add FIXP_Switch_Ingress.ipv4_forward 192.168.184.102 => FICP_Switch_Ingress.ipv4_SetSpec 000000000002 3"

                clientSocket.sendall(rule)

            except socket.error as err:
                print "socket error\n"
            except:
                print "exception\n"


            clientSocket.close()

def main():
    rule_handler()


if __name__ == '__main__':
    main()
