/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
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

struct metadata {
    bit<32> inp;
    bit<32> out1_1;
    bit<32> out1_2;
    bit<32> out1_3;
    bit<32> out1_4;
    bit<32> out1_5;
    bit<32> out1_6;
    bit<32> out1_7;
    bit<32> out1_8;
    bit<8> out2_1;
    bit<1> decision;
    bit<8> inp2;

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.inp = packet.lookahead<bit<32>>();
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action l1_xor_action(bit<32> w1, bit<32> w2, bit<32> w3, bit<32> w4, bit<32> w5, bit<32> w6, bit<32> w7, bit<32> w8) {
        meta.out1_1 = w1 ^ meta.inp;
        meta.out1_2 = w2 ^ meta.inp;
        meta.out1_3 = w3 ^ meta.inp;
        meta.out1_4 = w4 ^ meta.inp;
        meta.out1_5 = w5 ^ meta.inp;
        meta.out1_6 = w6 ^ meta.inp;
        meta.out1_7 = w7 ^ meta.inp;
        meta.out1_8 = w8 ^ meta.inp;
    }

    action l1_popcount_action() {
        if (meta.out1_1 == 0){
            meta.inp2[0:0] = 0;
        }else{
            meta.inp2[0:0] = 1;
        }

        if (meta.out1_2 == 0){
            meta.inp2[1:1] = 0;
        }else{
            meta.inp2[1:1] = 1;
        }

        if (meta.out1_3 == 0){
            meta.inp2[2:2] = 0;
        }else{
            meta.inp2[2:2] = 1;
        }

        if (meta.out1_4 == 0){
            meta.inp2[3:3] = 0;
        }else{
            meta.inp2[3:3] = 1;
        }

        if (meta.out1_5 == 0){
            meta.inp2[4:4] = 0;
        }else{
            meta.inp2[4:4] = 1;
        }

        if (meta.out1_6 == 0){
            meta.inp2[5:5] = 0;
        }else{
            meta.inp2[5:5] = 1;
        }

        if (meta.out1_7 == 0){
            meta.inp2[6:6] = 0;
        }else{
            meta.inp2[6:6] = 1;
        }

        if (meta.out1_8 == 0){
            meta.inp2[7:7] = 0;
        }else{
            meta.inp2[7:7] = 1;
        }
    }

    action l2_xor_action(bit<8> w1){
        meta.out2_1 = w1 ^ meta.inp2;
    }

    action l2_popcount_action(){
        if (meta.out2_1 == 0){
            meta.decision = 0;
        } else {
            meta.decision = 1;
        }
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table l1_xor {
        actions = { l1_xor_action; NoAction; }
        default_action = l1_xor_action(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000);
    }

    table l1_activation {
        actions = {l1_popcount_action; NoAction; }
        default_action = l1_popcount_action();
    }

    table l2_xor{
        actions = {l2_xor_action; NoAction; }
        default_action = l2_xor_action(0x00);
    }

    table l2_activation {
        actions = {l2_popcount_action; NoAction; }
        default_action = l2_popcount_action();
    }

    table decide {
        key = {
            meta.decision : exact;
        }
        actions = {NoAction ; drop ;}
        const entries = {
            (0) : NoAction();
        }
        default_action = NoAction();
    }



    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        l1_xor.apply();
        l1_activation.apply();
        l2_xor.apply();
        l2_activation.apply();
        decide.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
