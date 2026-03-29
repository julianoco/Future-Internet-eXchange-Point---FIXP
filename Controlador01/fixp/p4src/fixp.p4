/* FIXP-SWITCH - Future Internet eXchange Point switch
   autor: Jose Augusto Tagliassachi Gavazza
   email: gavazza@gmail.com
*/

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> xptoAddr_t;

header ethernet_t
{
    macAddr_t dst;
    macAddr_t src;
    bit<16>   type;
}

header ipv4_t
{
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header etarch_t
{
    bit<8>        cpl;
    bit<8>        cpt;
    bit<8>        cpid;
    bit<8>        pl;
}

header ng_t
{
    bit<8>       msgId;
    bit<8>       fragSeq;
    bit<8>       msgSize;
}

struct metadata
{
    /* empty */
}

struct headers
{
    ethernet_t ethernet;
    ipv4_t     ipv4;
    etarch_t   etarch;
    ng_t       ng;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser FIXP_Switch_Parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{

    state start
    {
        transition parse_ethernet;
    }

    state parse_ethernet
    {
        packet.extract(hdr.ethernet);

        transition select (hdr.ethernet.type)
        {
            0x0800: parse_ipv4;
            0x0880: parse_etarch;
            0x1234: parse_ng;
        }
    }

    state parse_ipv4
    {
        packet.extract(hdr.ipv4);

        transition accept;
    }

    state parse_etarch
    {
        packet.extract(hdr.etarch);
        //packet.extract(hdr.etarch, (bit<32>)(((bit<16>)hdr.etarch.pl) * 8));

        transition accept;
    }

    state parse_ng
    {
        packet.extract(hdr.ng);
        //packet.extract(hdr.ng, (bit<32>)(((bit<16>)hdr.ng.msgSize) * 8));
        
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control FIXP_Switch_VerifyChecksum(inout headers hdr, inout metadata meta)
{
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control FIXP_Switch_Ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{

    action SetSpec(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    action ToController()
    {
        standard_metadata.egress_spec = 1;
    }

    action ipv4_SetSpec(macAddr_t dstAddr, egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src = hdr.ethernet.dst;
        hdr.ethernet.dst = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action etarch_SetSpec(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    action ng_SetSpec(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    table ipv4_forward
    {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_SetSpec;
            ToController;
        }

        size = 1023;

        default_action = ToController();
    }

    table etarch_forward
    {
        key = {
            hdr.ethernet.src: exact;
        }

        actions = {
            etarch_SetSpec;
            ToController;
        }

        size = 1023;

        default_action = ToController();
    }

    table ng_forward
    {
        key = {
            hdr.ethernet.dst: exact;
        }

        actions = {
            ng_SetSpec;
            ToController;
        }

        size = 1023;

        default_action = ToController();
    }

    apply
    {
        if(hdr.ipv4.isValid())
        {
            ipv4_forward.apply();
        }

        if(hdr.etarch.isValid())
        {
            etarch_forward.apply();
        }

        if(hdr.ng.isValid())
        {
            ng_forward.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control FIXP_Switch_Egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control FIXP_Switch_ComputeChecksum(inout headers hdr, inout metadata meta)
{
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control FIXP_Switch_Deparser(packet_out packet, in headers hdr)
{
    apply
    {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.etarch);
        packet.emit(hdr.ng);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
FIXP_Switch_Parser(),
FIXP_Switch_VerifyChecksum(),
FIXP_Switch_Ingress(),
FIXP_Switch_Egress(),
FIXP_Switch_ComputeChecksum(),
FIXP_Switch_Deparser()
) main;
