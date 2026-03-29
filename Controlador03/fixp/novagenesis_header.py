from scapy.all import *
import sys, os

TYPE_NOVAGENESIS = 0x1234

class NOVAGENESIS(Packet):
    name = "NOVA GENESIS";

    fields_desc = [
        ByteField("msgId", 0),
        ByteField("fragSeq", 0),
        ByteField("msgSize", 0)
    ]
    def summary(self):
        return self.sprintf("msgId=%msgId% fragSeq=%fragSeq% msgSize=%msgSize%")

bind_layers(Ether, NOVAGENESIS, type=TYPE_NOVAGENESIS)

