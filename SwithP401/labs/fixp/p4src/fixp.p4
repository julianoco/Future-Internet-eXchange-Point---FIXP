/* FIXP-SWITCH - Future Internet eXchange Point switch
   autor: Jose Augusto Tagliassachi Gavazza - Ufscar
   email: gavazza@gmail.com

   autor: Juliano Coelho Goncalves de Melo  - UFU
	    - Parte destinada ao controlador etarch
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
{	           //nao e considerado o preambulo
    macAddr_t dst; //Endereco mac de destino
    macAddr_t src; //endereco mac de origem
    bit<16>   type; //tipo do protocolo encapsulado, ou seja, ethertype
		    //nao e considerado o CRC, CICLO DE REDUNDANCIA CICLICA
}

header ipv4_t
{
    bit<4>    version; //versao do protocolo
    bit<4>    ihl; //comprimento do cabecalho
    bit<8>    diffserv;  //type of service. diferentes tipos de datagramas ip
    bit<16>   totalLen;  //comprimento do datagrama (cabecalho + dados)
    bit<16>   identification; //recurso utilizado para fragmentacao
    bit<3>    flags; //recurso utilizado para fragmentacao
    bit<13>   fragOffset; //recurso utilizado para fragmentacao
    bit<8>    ttl; //tempo de vida
    bit<8>    protocol; //numero do protocolo da camada de transporte (6. tcp 17. udp)
    bit<16>   hdrChecksum; //campo para checar erros no datagrama IP
    ip4Addr_t srcAddr; //endereco ip de origem
    ip4Addr_t dstAddr; //endereco ip de destino
		      //aqui nao e considerada o campo opcoes do cabecalho ip
}

header tcp_t {
    bit<16> srcPort; //porta de origem
    bit<16> dstPort;  //porta de destino
    bit<32> seqNo;  //numero de sequencia
    bit<32> ackNo;  //numero de reconhecimento ack
    bit<4>  dataOffset; //comprimento do cabecalho tcp
    bit<3>  res;  //nao utilizado
    bit<3>  ecn; //nao utilizado
    bit<6>  ctrl;  //seis flags. URG ACK PSH RST SYN FIN
    bit<16> window; //janela de recepcao para controle de fluxo do tcp
    bit<16> checksum; //checksum soma de verificacao da internet
    bit<16> urgentPtr; //ponteiro de urgencia nao e usado
}

header udp_t {
    bit<16> srcPort; //numero da porta de origem
    bit<16> dstPort;  //numero da porta de destino
    bit<16> length_;  //comprimento do segmento UDP (cabecalho + dados)
    bit<16> checksum; //soma de verificacao para deteccao de erros
}

header raw_switch_t
{
    bit<16>     arquiteturaEncapsulada; //FOI ENCAPSULADA ASSIM POR EXEMPLO \x08\x80 -> 16 bits
    bit<8>      responsePrimitiveType;  //FOI ENCAPSULADO ASSIM PACK %3s -> 24 bits 8 do s e 16 do 01 ou 02 ou 03 etc...
    bit<16>     switchEtarch;           //ACIMA TEM A EXPLICACAO
    bit<16>	portEtarch;             //>H com pack equivale a 2 bytes
}

/*
header raw_switch2_t
{
    bit<328>    responsePrimitiveType;
}*/

/*
     response responsePrimitiveType corresponde ao primeiro byte do que anexei na resposta Etarch
     switchEtarch corresponde ao numero do switch etarch porque foi codificado 2 bytes para essa informacao
     portEtarch corresponde a porta etarch porque foi codificado dois bytes para essa informacao
     etarch_switch_t e etarch_switch_2_t sao cabelcalhos do etarch referente ao packet-out
     etarch nao está fazendo packet-out geral, foi o primeiro controlador, entao faz manual
     etarch_t_ representa o payload de controle que o cliente envia para o dtsa
*/
header etarch_switch_t
{
    bit<8>      responsePrimitiveType;
    bit<16>     switchEtarch;
    bit<16>	portEtarch;
}

/*
  aqui pega o restante de Raw(dos dados) do pacote que complementa o minimo de 46 bytes de pacote
*/
header etarch_switch_2_t
{
    bit<328>	cabEtarch;  //mínimo do payload(dados) Ethernet tirando os 5 bytes de etarch_switch_t	
}

//acho que abaixo está errado. não é preciso retirar os dados, só os cabeçalhos
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

            (0x0900,0x464958500000,_)    : accept;               //FLOW_MOD - REQUISICAO VAI SER DROPADO   0x464958500000 = FIXP
            (0x0900,_,0x464958500000)    : accept;               //FLOW_MOD - RESPOSTA VAI SER DROPADO
            (0x0900,_,_)    	         : parse_fixp_switch;    //PACKET_OUT GERAL DE QUALQUER ARQUITETURA

            (0x0880,0x445453000000,_)    : parse_etarch;         //packet_in ETARCH    0x445453000000 = 'DTS'
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

    /*parei aqui. Pelo que tudo indica os parâmetros da acao é passado pelo comando table add*/
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
        //nao fez matching, mas se trata de um pacote de controle enviado para o client, ou seja, do dtsa para o client
        //trata-se de um packetout
        if(hdr.etarch_switch.isValid()) {
	  //fazer teste que verifica se o pacote pertence a esse switch 
          if((hdr.etarch_switch.responsePrimitiveType == P4_SWITCH) && (hdr.etarch_switch.switchEtarch == P4_SWITCH_ID)) { 
  	    standard_metadata.egress_spec = (bit <9>)(hdr.etarch_switch.portEtarch);
          }
          else {
	    standard_metadata.egress_spec = P4_DROP_PORT;
          }	  
	}
	else {
	  //nao fez matching, entao o pacote de controle vai ser enviado para o controlador (packet in)
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
	
        //documentado atualstandard_metadata.egress_spec = port;
        //hdr.ethernet.src = hdr.ethernet.dst;
        //hdr.ethernet.dst = dstAddr;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ToMakePacketOut()
    {
        //se eu consigo extrair dados do pacote e manda-los sem a extracao, sera que que consigo adiconar dados ao pacote?
        //acho que sim, mas tenho que testar. arranjar um jeito de criar um struct parecido com o header, preenche-lo e envia-lo
        //acho que vai ser possivel fazer isso.   

	//bit<16>     arquiteturaEncapsulada; //FOI ENCAPSULADA ASSIM POR EXEMPLO \x08\x80 -> 16 bits
    	//bit<8>      responsePrimitiveType;  //FOI ENCAPSULADO ASSIM PACK %3s -> 24 bits 8 do s e 16 do 01 ou 02 ou 03 etc...
        //bit<16>     switchEtarch;           //ACIMA TEM A EXPLICACAO
        //bit<16>	portEtarch;             //>H com pack equivale a 2 bytes
     
	if((hdr.raw_switch.responsePrimitiveType == P4_SWITCH) && (hdr.raw_switch.switchEtarch == P4_SWITCH_ID)) { 
	    hdr.ethernet.type = hdr.raw_switch.arquiteturaEncapsulada; //0x0800 //no nosso caso ip
  	    standard_metadata.egress_spec = (bit <9>)(hdr.raw_switch.portEtarch);	    
        }
        else {
        //caso a mensagem seja um packet-out mas nao pertence ao switch, dropa
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
            //Executei a acao direto sem precisar passar por uma tabela
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

        //na porta de egresso se egress_port = ingress_port, dropar a mensagem.
        //objetivo: para nao mandar o pacote pela mesma porta de onde veio
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
		
	//o etarch_switch abaixo nunca sera mandado pois trata-se das informacoes adicionais enviadas
        //pelo controlador para fazer o packet out, quais informacoes? a letra s, o numero do switch e o numero da porta
        //packet.emit(hdr.etarch_switch);
        //quando voce tira essa parte, o pacote original volta ao normal
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
