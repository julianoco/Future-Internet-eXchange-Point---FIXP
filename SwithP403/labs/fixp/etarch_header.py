from scapy.all import *
import sys, os

TYPE_ETARCH = 0x0880

class ETARCH(Packet):
    name = "ETARCH";

    fields_desc = [
        ByteField("cpl", 0),
        ByteField("cpt", 0),
        ByteField("cpid", 0),
#        ByteField("pl", 0),
        FieldLenField("pl", None, length_of="p"),
        StrLenField("p", "", length_from=lambda pkt:pkt.pl)
    ]
    def summary(self):
        return self.sprintf("cpl=%cpl% cpt=%cpt% cpid=%cpid% pl=%pl%")

bind_layers(Ether, ETARCH, type=TYPE_ETARCH)

