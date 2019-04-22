/*
 * This is a script based on Thomar NAT and using DPDK for I/O. One  
 * can replace the FromDPDKDevice and ToDPDKDevice with FromDevice 
 * and Queue -> ToDevice to use standard I/O.
 *
 * See also thomer-nat.click and mazu-nat.click
 *
 * Author: Hongyi Zhang <hongyiz@kth.se>
 * Modified by: Rishabh Iyer <rishabh.iyer@epfl.ch>
 */

define(
 $iface0    1,
 $iface1    0,
 $queueSize 1024,
 $burst     32
);

AddressInfo(
    lan_interface    192.168.6.2   10.0.0.0/8        90:e2:ba:55:14:11,
    wan_interface    192.168.4.10  192.168.4.10/27   90:e2:ba:55:14:10
);

// Module's I/O
nicIn0  :: FromDPDKDevice($iface0, BURST $burst);
nicOut0 :: ToDPDKDevice  ($iface0, IQUEUE $queueSize, BURST $burst);

nicIn1  :: FromDPDKDevice($iface1, BURST $burst);
nicOut1 :: ToDPDKDevice  ($iface1, IQUEUE $queueSize, BURST $burst);

class_left :: Classifier(12/0806 20/0001,  //ARP query
                         12/0806 20/0002,  // ARP response
                         12/0800); //IP

arpq_left :: ARPQuerier(lan_interface) -> nicOut0; //The packet will go to lan interface

class_right :: Classifier(12/0806 20/0001,  //ARP query
                         12/0806 20/0002,  // ARP response
                         12/0800); //IP

arpq_right :: ARPQuerier(wan_interface) -> nicOut1; //The packet will go to wan interface

ee_left :: EnsureEther(0x0800, 1:1:1:1:1:0,90:e2:ba:55:14:10);
ee_right :: EnsureEther(0x0800, 1:1:1:1:1:1,90:e2:ba:55:14:11); 

ip_rw_l :: IPClassifier(proto tcp, proto udp, -);
ip_rw_r :: IPClassifier(proto tcp, proto udp, -);

rwpattern :: IPRewriterPatterns(FW - - - -);
tcp_rw :: TCPRewriter(pattern FW 0 1, pass 1, MAPPING_CAPACITY 65536);
udp_rw :: UDPRewriter(pattern FW 0 1, pass 1, MAPPING_CAPACITY 65536);

/* All packets come in through the ARPQuerier, but will go out via an EnsureEther element, because our machines don't reply to ARPs */

nicIn0 -> class_left;

class_left[0] -> ARPResponder(lan_interface) -> nicOut0;
class_left[1] -> [1]arpq_left;
class_left[2] -> Strip(14)-> CheckIPHeader -> ip_rw_l;

ip_rw_l[0] -> [0]tcp_rw;    //Rewrite the packet and foward to wan interface
ip_rw_l[1] -> [0]udp_rw;

//For debugging
//ip_rw_l[0] -> IPPrint(ip_rw_l0) -> [0]tcp_rw;    //Rewrite the packet and foward to wan interface
//ip_rw_l[1] -> IPPrint(ip_rw_l1) -> [0]udp_rw;


tcp_rw[0]   -> ee_right[0] -> nicOut1;
udp_rw[0]   -> ee_right[0] -> nicOut1;

nicIn1 -> class_right;

class_right[0] -> ARPResponder(wan_interface) -> nicOut1;
class_right[1] -> [1]arpq_right;
class_right[2] -> Strip(14)-> CheckIPHeader -> ip_rw_r;

ip_rw_r[0] -> [1]tcp_rw;   //If we have the mapping, forward the packet to lan interface
ip_rw_r[1] -> [1]udp_rw;

//For debugging
//ip_rw_r[0] -> IPPrint(ip_rw_r0) -> [1]tcp_rw;   //If we have the mapping, forward the packet to lan interface
//ip_rw_r[1] -> IPPrint(ip_rw_r1) -> [1]udp_rw;


tcp_rw[1]   -> ee_left[0] -> nicOut0;
udp_rw[1]   -> ee_left[0] -> nicOut0;

//---------------------icmp error----------------------
// Rewriting rules for ICMP error packets
icmp_erw :: ICMPRewriter(tcp_rw icmp_rw);
icmp_erw[0] -> arpq_left[0] -> nicOut0;

//---------------------icmp echo-----------------------

icmp_rw :: ICMPPingRewriter(pattern FW 0 1, pass 1);
icmp_rw[0] -> arpq_right[0] -> nicOut1;
icmp_rw[1] -> arpq_left[0] -> nicOut0;


ip_rw_l[2] -> pk_select :: IPClassifier(icmp type echo);
pk_select[0]-> [0]icmp_rw;

ip_rw_r[2] ->  icmp_type :: IPClassifier(icmp type echo-reply, proto icmp);
icmp_type[0] -> [1]icmp_rw;
icmp_type[1] -> [0]icmp_erw;
