# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import icmp
from ryu.controller.handler import CONFIG_DISPATCHER

"""
fill in the code here (optional)
"""
left_LAN_ARP_table = {
	'192.168.1.2': '00:00:00:00:01:02',
	'192.168.1.3': '00:00:00:00:01:03'
}

right_LAN_ARP_table = {
	'192.168.2.2': '00:00:00:00:02:02',
	'192.168.2.3': '00:00:00:00:02:03'
}

s2_switch_ports = {
    'VLAN_100_access_ports': (2, 3),
    'VLAN_200_access_ports': (4,),
    'trunk_port': (1,)
}

s3_switch_ports = {
    'VLAN_100_access_ports': (4,),
    'VLAN_200_access_ports': (2, 3),
    'trunk_port': (1,)
}

s2_s3_switch_ports = {
    2: s2_switch_ports,
    3: s3_switch_ports
}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    #Proactive forwarding of the high-priority traffic(the traffic with non-zero ToS) between the routers
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        if dpid == 0x1A:
            self.add_proactive_tos_forwarding(
                dp = datapath, 
                dest_ip = '192.168.2.0',
                source_mac = "00:00:00:00:05:01",
                dest_mac = "00:00:00:00:05:02",
                out_port = 4)
        elif dpid == 0x1B:      
            self.add_proactive_tos_forwarding(
                dp = datapath, 
                dest_ip = '192.168.1.0',
                source_mac = "00:00:00:00:05:02",
                dest_mac = "00:00:00:00:05:01",
                out_port = 4)      
   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        
        #Check if the packet is IPv6 (Ethertype 0x86dd)
        if ethertype == ether_types.ETH_TYPE_IPV6:
            self.logger.info("IPv6 packet in %s %s %s %s in_port=%s\n", hex(dpid), hex(ethertype), src, dst, msg.in_port)
            return  #Exit the handler

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)
        
        packet_arp = pkt.get_protocol(arp.arp)
        packet_ip = pkt.get_protocol(ipv4.ipv4)
        
        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                #3.Static routing with two routers
                if packet_arp.opcode == arp.ARP_REQUEST:
                    if packet_arp.dst_ip == '192.168.1.1': #Left LAN
                            self.arp_reply(
                                action_list = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)], 
                                dp=datapath, 
                                source_mac="00:00:00:00:01:01", 
                                dest_mac=src, 
                                source_ip=packet_arp.dst_ip, 
                                dest_ip=packet_arp.src_ip
                            )
                    else: 
                        return
                    
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """
                #3.Static routing with two routers
                dest_ip = packet_ip.dst
                if '192.168.1.' in dest_ip and dest_ip in left_LAN_ARP_table:
                    self.logger.info("Packet in left LAN: %s ----> %s\n", packet_ip.src, dest_ip)
                    self.ip_match_and_forward(datapath, "00:00:00:00:01:01", left_LAN_ARP_table[dest_ip], dest_ip, 32, 2, pkt)
                    
                elif '192.168.2.' in dest_ip:
                    self.logger.info("Packet in router 1B: %s ----> %s\n", packet_ip.src, dest_ip)
                    self.ip_match_and_forward(datapath, "00:00:00:00:03:01", "00:00:00:00:03:02", dest_ip, 24, 1, pkt)
                        
                else:
                    #ICMP "Destination Host Unreachable" packet
                    if msg.in_port == 1:
                        source_mac = '00:00:00:00:03:01'
                        dest_mac = '00:00:00:00:03:02'
                    elif msg.in_port == 2:
                        source_mac = '00:00:00:00:01:01'
                        dest_mac = eth.src
                    elif msg.in_port == 4:
                        source_mac = '00:00:00:00:05:01'
                        dest_mac = '00:00:00:00:05:02'
                    
                    self.logger.info("ICMP Reply Packet for Unreachable Destination: %s ----> %s\n", source_mac, dest_mac)
                    data = msg.data[14:]
                    #Extract the IP header and the first 8 bytes of the IP payload(info from transport layer)
                    ip_header_len = 20  #Typical IP header length
                    min_data_len = ip_header_len + 8
                    if len(data) > min_data_len:
                        data = data[:min_data_len]

                    #Keeps the actual data(payload) of the packet and add icmp info in the new packet reply
                    self.icmp_reply(
                        action_list = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)], 
                        data = data,
                        source_mac = source_mac,
                        dest_mac = dest_mac,
                        source_ip = '192.168.1.1',
                        packet_source_ip = packet_ip.src,
                        dp = datapath
                    )
                    return
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                #3.Static routing with two routers
                if packet_arp.opcode == arp.ARP_REQUEST:
                    if packet_arp.dst_ip == '192.168.2.1': #Left LAN
                            self.arp_reply(
                                action_list = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)], 
                                dp=datapath, 
                                source_mac="00:00:00:00:02:01", 
                                dest_mac=src, 
                                source_ip=packet_arp.dst_ip, 
                                dest_ip=packet_arp.src_ip
                            )
                    else: 
                        return
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """
                #3.Static routing with two routers
                dest_ip = packet_ip.dst
                if '192.168.1.' in dest_ip:
                    self.logger.info("Packet in router 1A: %s ----> %s\n", packet_ip.src, dest_ip)
                    self.ip_match_and_forward(datapath, "00:00:00:00:03:02", "00:00:00:00:03:01", dest_ip, 24, 1, pkt)
                    
                elif '192.168.2.' in dest_ip and dest_ip in right_LAN_ARP_table:
                    self.logger.info("Packet in right LAN: %s ----> %s\n", packet_ip.src, dest_ip)
                    self.ip_match_and_forward(datapath, "00:00:00:00:02:01", right_LAN_ARP_table[dest_ip], dest_ip, 32, 2, pkt)
                    
                else:
                    #ICMP "Destination Host Unreachable" packet
                    if msg.in_port == 1:
                        source_mac = '00:00:00:00:03:02'
                        dest_mac = '00:00:00:00:03:01'
                    elif msg.in_port == 2:
                        source_mac = '00:00:00:00:02:01'
                        dest_mac = eth.src
                    elif msg.in_port == 4:
                        source_mac = '00:00:00:00:05:02'
                        dest_mac = '00:00:00:00:05:01'
                    
                    self.logger.info("ICMP Reply Packet for Unreachable Destination: %s ----> %s\n", source_mac, dest_mac)
                    data = msg.data[14:]
                    #Extract the IP header and the first 8 bytes of the IP payload(info from transport layer)
                    ip_header_len = 20  #Typical IP header length
                    min_data_len = ip_header_len + 8
                    if len(data) > min_data_len:
                        data = data[:min_data_len]
                    #Keeps the actual data(payload) of the packet and add icmp info in the new packet reply
                    self.icmp_reply(
                        action_list = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)], 
                        data = data,
                        source_mac = source_mac,
                        dest_mac = dest_mac,
                        source_ip = '192.168.2.1',
                        packet_source_ip = packet_ip.src,
                        dp = datapath
                    )
                    return 
                return
            return
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port
        
        #Get vlan id of switch's port
        for vlan_key in s2_s3_switch_ports[dpid]:
            if 'VLAN_' in vlan_key and msg.in_port in s2_s3_switch_ports[dpid][vlan_key]:
                vlanId = int(vlan_key.split('_')[1])  #Extract VLAN ID from the key
                break
        
        actions = []
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            #Check if packet came from trunk port and extract vid (decapsulate)
            if ethertype == ether_types.ETH_TYPE_8021Q:
                vlanPacket = pkt.get_protocol(vlan.vlan)
                vlanId = vlanPacket.vid
                actions.append(datapath.ofproto_parser.OFPActionStripVlan())
                
            #If to be sent to trunk port tag it (encapsulate)
            if out_port in s2_switch_ports["trunk_port"] or out_port in s3_switch_ports["trunk_port"]:
                actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlanId))
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
            else :
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        else: #Flooding
            out_port = ofproto.OFPP_FLOOD
            #Flood to all access ports and trunk port but not to in-port
            for out_port_access in s2_s3_switch_ports[dpid]['VLAN_100_access_ports']:
                if out_port_access != msg.in_port:
                    #Decapsulate if came from trunk port
                    if ethertype == ether_types.ETH_TYPE_8021Q:
                        actions.append(datapath.ofproto_parser.OFPActionStripVlan())
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port_access))
                    
            for out_port_access in s2_s3_switch_ports[dpid]['VLAN_200_access_ports']:
                if out_port_access != msg.in_port:
                    #Decapsulate if came from trunk port
                    if ethertype == ether_types.ETH_TYPE_8021Q:
                        actions.append(datapath.ofproto_parser.OFPActionStripVlan())
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port_access))
                
            #Flood to trunk port
            for out_port_trunk in s2_s3_switch_ports[dpid]['trunk_port']:
                if out_port_trunk != msg.in_port:
                    #Decapsulate if came from trunk port
                    if ethertype == ether_types.ETH_TYPE_8021Q:
                        actions.append(datapath.ofproto_parser.OFPActionStripVlan())
                    actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlanId))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port_trunk))
                    
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        
        #If the packet came from access port
        if ethertype != ether_types.ETH_TYPE_8021Q:
            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=eth.dst)
        else : #If the packet came from trunk port
            vlanPacket = pkt.get_protocol(vlan.vlan)
            match = datapath.ofproto_parser.OFPMatch(
                dl_vlan=vlanPacket.vid, in_port=msg.in_port, dl_dst=eth.dst)

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)
        else :
            return

    """
    fill in the code here for the ARP reply functions.
    """
    #Function that is called for ARP packets to fill the ARP table
    def arp_reply(self, action_list, dp, source_mac, dest_mac, source_ip, dest_ip):
        #Get the OpenFlow protocol object for the datapath (switch)
        ofproto = dp.ofproto

        #Create a new packet for the ARP reply
        arp_reply_packet = packet.Packet()
        
        #Add an Ethernet frame to the packet with the appropriate ethertype, destination MAC, and source MAC
        arp_reply_packet.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP, dst=dest_mac, src=source_mac))
        
        #Add an ARP protocol frame to the packet with the ARP reply opcode and the source and destination MAC and IP addresses
        arp_reply_packet.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=source_mac, src_ip=source_ip, dst_mac=dest_mac, dst_ip=dest_ip))

        #Serialize the packet to prepare it for sending
        arp_reply_packet.serialize()

        #Create an OpenFlow PacketOut message to send the ARP reply packet
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
            actions=action_list, data=arp_reply_packet.data
        )
        #Log the ARP reply being sent with the source and destination MAC and IP addresses
        self.logger.info("The ARP Reply is: SourceMAC: %s SourceIP: %s to DestinationMAC: %s DestinationIP: %s]\n", source_mac, source_ip, dest_mac, dest_ip)
        #Send the PacketOut message to the datapath (switch)
        dp.send_msg(out)
    
    #Function that is called for IP packets to fill the flow table
    def ip_match_and_forward(self, dp, source_mac, dest_mac, dest_ip, mask, out_port, pkt):
        #Get the OpenFlow protocol object for the datapath (switch)
        ofproto = dp.ofproto
                
        #Define the actions to be taken on the packet           
        action_list = [
            dp.ofproto_parser.OFPActionSetDlSrc(source_mac),
            dp.ofproto_parser.OFPActionSetDlDst(dest_mac),
            dp.ofproto_parser.OFPActionOutput(out_port)
        ]
        
        #Define the IP mask based on the provided subnet mask. Mask is either 24 or 32
        ip_mask = mask
        
        #Create a PacketOut message to send the packet immediately
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, 
            buffer_id=ofproto.OFP_NO_BUFFER, 
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action_list, 
            data=pkt.data
            )
        #Send the PacketOut message to the datapath (switch)
        dp.send_msg(out)

        #Create a match object to match IP packets with the specified destination IP and mask
        match = dp.ofproto_parser.OFPMatch(
            dl_type=ether_types.ETH_TYPE_IP,
            nw_dst=dest_ip,
            nw_dst_mask=ip_mask
            )
        #Add the flow entry to the switch with the specified match and actions
        self.add_flow(dp, match, action_list)
    
    #Function that handles the received packets in the routers that are destined to an unknown IP address   
    def icmp_reply(self, action_list, data, source_mac, dest_mac, source_ip, packet_source_ip, dp):
        #Get the OpenFlow protocol object for the datapath (switch)
        ofproto = dp.ofproto

        #Create a new packet for the ICMP reply
        icmp_reply_packet = packet.Packet()
        
        #Add an Ethernet frame to the packet with the appropriate ethertype, destination MAC, and source MAC
        icmp_reply_packet.add_protocol(
            ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_IP, 
                dst=dest_mac,
                src=source_mac
            )
        )
        
        #Add an ARP protocol frame to the packet with the ARP reply opcode and the source and destination MAC and IP addresses
        icmp_reply_packet.add_protocol(
            ipv4.ipv4(
                dst=packet_source_ip, 
                src=source_ip, 
                proto=inet.IPPROTO_ICMP
            )
        )
        
        #Add an ICMP protocol header to the icmp_reply packet
        icmp_reply_packet.add_protocol(
            icmp.icmp(
                type_=icmp.ICMP_DEST_UNREACH, 
                code=icmp.ICMP_HOST_UNREACH_CODE,
                data=icmp.dest_unreach(
                    data_len=len(data),
                    data=data
                )
            )
        )
        
        #Serialize the packet to prepare it for sending
        icmp_reply_packet.serialize()

        #Create an OpenFlow PacketOut message to send the ICMP reply packet
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, 
            buffer_id=ofproto.OFP_NO_BUFFER, 
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action_list, 
            data=icmp_reply_packet.data
        )
        dp.send_msg(out)
    
    #Function that handles proactive forwarding for high priority traffic    
    def add_proactive_tos_forwarding(self, dp, dest_ip, source_mac, dest_mac, out_port):
        #Define the actions to be taken on the packet
        action_list = [
                dp.ofproto_parser.OFPActionSetDlSrc(source_mac),
                dp.ofproto_parser.OFPActionSetDlDst(dest_mac),
                dp.ofproto_parser.OFPActionOutput(out_port)
            ]
        
        #Create a match object to match IP packets with the specified destination IP and mask
        match = dp.ofproto_parser.OFPMatch(
                dl_type=ether_types.ETH_TYPE_IP,
                nw_dst=dest_ip, nw_dst_mask=24, 
                nw_tos=8
            )
        
        #Add the flow entry to the switch with the specified match and actions
        self.add_flow(dp, match, action_list)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
