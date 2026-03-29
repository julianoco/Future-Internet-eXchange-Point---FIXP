/* FIXP-SWITCH - Future Internet eXchange Point switch
   autor: Jose Augusto Tagliassachi Gavazza - Ufscar
   email: gavazza@gmail.com

   autor: Juliano Coelho Goncalves de Melo  - UFU
	    - Parte destinada ao controlador ETArch
	    - Parte destinada ao protocolo FIXP (generico - packet_out; flow_mod (descarte))
	    - Parte destinada ao controlador IPv4
	    - Parte destinada às trocas de mensagens UDP
            - Parte destinada ao controlador do SIMULADOR DO NOVA GENESIS	
	    - Parte destinada à reinserção dos dados automaticamente por packet out
   email: julianoco@yahoo.com   
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
typedef bit<16> mcastGroup_t;

const bit<8>  P4_SWITCH    = 0x73;   //letra s
const bit<16> P4_SWITCH_ID = 0x3031; //01
const bit<9>  P4_DROP_PORT = 0x1ff;  //511

//if((hdr.etarch_switch.responsePrimitiveType == ) && (hdr.etarch_switch.switchEtarch == 0x3031)) { 

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header raw_switch_t
{
    bit<16>     arquiteturaEncapsulada;
    bit<8>      responsePrimitiveType;
    bit<16>     switchEtarch;
    bit<16>	portEtarch;
}

/*
header raw_switch2_t
{
    bit<328>    responsePrimitiveType;
}*/

header etarch_switch_t
{
    bit<8>      responsePrimitiveType;
    bit<16>     switchEtarch;
    bit<16>	portEtarch;
}

header etarch_switch_2_t
{
    bit<328>	cabEtarch;  //mínimo do payload(dados) Ethernet	
}

header etarch_t
{
    bit<368>	cabEtarch;  //mínimo do payload(dados) Ethernet	
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
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    //tcp_t             tcp;
    //udp_t             udp;    
    raw_switch_t      raw_switch;
    //raw_switch2_t     raw_switch2;	
    etarch_switch_t   etarch_switch;
    etarch_switch_2_t etarch_switch_2;
    etarch_t          etarch;

    ng_t              ng;
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

        transition select(hdr.ethernet.type, hdr.ethernet.dst, hdr.ethernet.src)
        {

            (0x800,_,_)		         : parse_ipv4;

            (0x0900,0x464958500000,_)    : accept;               //FLOW_MOD
            (0x0900,_,0x464958500000)    : accept;               //FLOW_MOD
            (0x0900,_,_)    	         : parse_fixp_switch;    //PACKET_OUT GERAL DE QUALQUER ARQUITETURA

            (0x0880,0x445453000000,_)    : parse_etarch;         //packet_in ETARCH
            (0x0880,0xffffffffffff,_)    : parse_etarch_switch;  //packet_out ETARCH
	    (0x0880,_,_)                 : parse_etarch; 	 //dados ETARCH

            (0x1235,0x445453000000,_)    : parse_etarch;         //packet_in  SIMULACAO NOVA GENESIS 
            (0x1235,0xffffffffffff,_)    : parse_etarch_switch;  //packet_out SIMULACAO NOVA GENESIS 
	    (0x1235,_,_)                 : parse_etarch; 	 //dados      SIMULACAO NOVA GENESIS 

            (0x1234,_,_)                 : parse_ng;             //ng
        }

    }

    state parse_ipv4
    {
        packet.extract(hdr.ipv4);

        transition accept;
    }    

    state parse_fixp_switch
    {
        packet.extract(hdr.raw_switch);
	transition accept;
	/*
        transition select(hdr.ipv4.protocol)
        {
            (0x11) : parse_ipv4_UDP; 	       //UDP
        }
	*/
    }
    
    state parse_raw_switch
    {
        packet.extract(hdr.raw_switch);                
	transition accept;		
    }


    state parse_etarch_switch
    {

        packet.extract(hdr.etarch_switch);                
	transition parse_etarch_switch_2;	
	
    }


    state parse_etarch_switch_2
    {
        packet.extract(hdr.etarch_switch_2);
        transition accept;
    }    

    state parse_etarch
    {
        //packet.extract(hdr.etarch, (bit<32>)(((bit<16>)hdr.etarch.pl) * 8));
        packet.extract(hdr.etarch);	
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

    action ToControllerEtharc()
    {	
      
        if(hdr.etarch_switch.isValid()) {

	  //fazer teste que verifica se o pacote pertence a esse switch o no parser
          if((hdr.etarch_switch.responsePrimitiveType == P4_SWITCH) && (hdr.etarch_switch.switchEtarch == P4_SWITCH_ID)) { 
  	    standard_metadata.egress_spec = (bit <9>)(hdr.etarch_switch.portEtarch);
          }
          else {
	    standard_metadata.egress_spec = P4_DROP_PORT;
          }	  
	}
	else {
          if(hdr.etarch.isValid()) {
            standard_metadata.egress_spec = 1;
  	  }
	}

    }


    action ToControllerEtharcNG() //SIMULACAO NG
    {	
      
        if(hdr.etarch_switch.isValid()) {

	  //fazer teste que verifica ase o pacote pertence a esse switch o no parser
          if((hdr.etarch_switch.responsePrimitiveType == P4_SWITCH) && (hdr.etarch_switch.switchEtarch == P4_SWITCH_ID)) { 
  	    standard_metadata.egress_spec = (bit <9>)(hdr.etarch_switch.portEtarch);
          }
          else {
	    standard_metadata.egress_spec = P4_DROP_PORT;
          }	  
	}
	else {
          if(hdr.etarch.isValid()) {
            standard_metadata.egress_spec = 1;
  	  }
	}

    }

    action ipv4_SetSpec(egressSpec_t port)
    {

	standard_metadata.egress_spec = port;

	/*
        if(hdr.raw_switch.isValid()) {

          if((hdr.raw_switch.responsePrimitiveType == P4_SWITCH) && (hdr.raw_switch.switchEtarch == P4_SWITCH_ID)) { 
	    hdr.ethernet.type = 0x800;
  	    standard_metadata.egress_spec = (bit <9>)(hdr.raw_switch.portEtarch);	    
          }
          else {
	    standard_metadata.egress_spec = P4_DROP_PORT;
          }	  

        }
	*/
	
        standard_metadata.egress_spec = port;
        //hdr.ethernet.src = hdr.ethernet.dst;
        //hdr.ethernet.dst = dstAddr;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ToMakePacketOut()
    {
	if((hdr.raw_switch.responsePrimitiveType == P4_SWITCH) && (hdr.raw_switch.switchEtarch == P4_SWITCH_ID)) { 
	    hdr.ethernet.type = hdr.raw_switch.arquiteturaEncapsulada; //0x0800
  	    standard_metadata.egress_spec = (bit <9>)(hdr.raw_switch.portEtarch);	    
        }
        else {
	    standard_metadata.egress_spec = P4_DROP_PORT;
        }	          
    }

    action dropPrimitive() {
	standard_metadata.egress_spec = P4_DROP_PORT;
    }

    action etarch_SetSpec(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    action etarch_SetSpec_Group(mcastGroup_t mcastGroup)
    {
	standard_metadata.mcast_grp = mcastGroup;
    }

    action etarch_SetSpec_Group_NG(mcastGroup_t mcastGroup)
    {
	standard_metadata.mcast_grp = mcastGroup;
    }

    action ng_SetSpec(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    table ipv4_forward
    {
        key = {
            //hdr.ipv4.dstAddr: lpm; #modificado para funcionamento do FIXP
	    hdr.ipv4.dstAddr: exact;
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
            hdr.ethernet.dst: exact;
        }

        actions = {
            etarch_SetSpec_Group;
            ToControllerEtharc;
        }

        //size = 1023;

        default_action = ToControllerEtharc();
    }

    table etarch_forward_ng //simulacao nova genesis
    {
        key = {
            hdr.ethernet.dst: exact;
        }

        actions = {
            etarch_SetSpec_Group_NG; //simulacao NG
            ToControllerEtharcNG;  //Simulacao NG
        }

        //size = 1023;

        default_action = ToControllerEtharcNG();
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
        } else if(hdr.raw_switch.isValid())
	{
	    ToMakePacketOut();
	} else if( (hdr.ethernet.isValid()) && (hdr.ethernet.type == 0x0880)) //if(hdr.etarch.isValid())
        {							              //para não cair nesse laço quando for apenas ethernet	
            etarch_forward.apply();
	    //ToControllerEtharc();	    
        } else if( (hdr.ethernet.isValid()) && (hdr.ethernet.type == 0x1235)) //if(hdr.etarch.isValid())
        {	    						              //para não cair nesse laço quando for apenas ethernet
            etarch_forward_ng.apply();
	    //ToControllerEtharc();	    
        } else if(hdr.ng.isValid())
        {
            ng_forward.apply();
        }
	else{
	    dropPrimitive();
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
    apply { 

	if( (hdr.ethernet.isValid()) && (hdr.ethernet.type == 0x0880 || hdr.ethernet.type == 0x1235))	{
	
		if(standard_metadata.egress_port == standard_metadata.ingress_port) {
			standard_metadata.egress_spec = P4_DROP_PORT;			
		}
		
	}

    }

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
        //packet.emit(hdr.udp);                
		
        //packet.emit(hdr.etarch_switch);
	packet.emit(hdr.etarch_switch_2);

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
