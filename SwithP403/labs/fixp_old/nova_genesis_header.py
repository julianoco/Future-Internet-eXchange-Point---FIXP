from scapy.all import *
import sys, os

TYPE_NOVA_GENESIS = 0x1234

class NOVA_GENESIS(Packet):
    name = "NOVA GENESIS";

    fields_desc = [
        ByteField("msgId", 0),
        ByteField("fragSeq", 0),
        FieldLenField("msgSize", None, length_of="ngMessage"),
        StrLenField("ngMessage", "", length_from=lambda pkt:pkt.msgSize)
    ]
    def summary(self):
        return self.sprintf("msgId=%msgId% fragSeq=%fragSeq% msgSize=%msgSize% ngMessage=%ngMessage%")

bind_layers(Ether, NOVA_GENESIS, type=TYPE_NOVA_GENESIS)

