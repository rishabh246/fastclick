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
 $iface0    0,
 $iface1    1,
 $queueSize 1024,
 $burst 32
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

lpm :: DirectIPLookup( /* Insert routes here */
                       18.26.4.24/32 0, /* Own address */
					   10.0.0.1/16 2,
					   10.7.0.0/16 2,
					   192.168.4.10/32 1 /* Tested address */
                       );
ee_left :: EnsureEther(0x0800, 1:1:1:1:1:0,90:e2:ba:55:14:10);
ee_right :: EnsureEther(0x0800, 1:1:1:1:1:0,90:e2:ba:55:14:11);

nicIn0 -> Strip(14) -> CheckIPHeader -> [0]lpm;
nicIn1 -> Strip(14) -> CheckIPHeader -> [0]lpm;

lpm[0]-> Discard /* Drop own packets */

lpm[1] -> ee_left[0] -> nicOut1;
lpm[2] -> ee_right[0] -> nicOut0;
