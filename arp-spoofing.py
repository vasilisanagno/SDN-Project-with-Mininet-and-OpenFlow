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
An OpenFlow 1.0 L3 Static Router and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether

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

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port
        
        packet_arp = pkt.get_protocol(arp.arp)
        
        if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
            #Check if h1 sends traffic to h2 to handle the ARP REPLY from the switch
            if packet_arp.src_mac == '00:00:00:00:00:01':
                """
                fill in the code here for the ARP requests operation, creating and sending ARP replies.
                """
                if packet_arp.opcode == arp.ARP_REQUEST:
                    #Call the arp_reply function for 1.ARP spoofing
                    self.arp_reply(
                        action_list=[datapath.ofproto_parser.OFPActionOutput(msg.in_port)],
                        dp=datapath,
                        source_mac='00:00:00:00:00:02',  #h2 MAC address
                        dest_mac=packet_arp.src_mac,
                        source_ip=packet_arp.dst_ip,
                        dest_ip=packet_arp.src_ip
                    )
                return
            elif packet_arp.src_mac == '00:00:00:00:00:02':
                if packet_arp.opcode == arp.ARP_REQUEST:
                    #Call the arp_reply function for 1.ARP spoofing
                    self.arp_reply(
                        action_list=[datapath.ofproto_parser.OFPActionOutput(msg.in_port)],
                        dp=datapath,
                        source_mac='00:00:00:00:00:01',  #h1 MAC address
                        dest_mac=packet_arp.src_mac,
                        source_ip=packet_arp.dst_ip,
                        dest_ip=packet_arp.src_ip
                    )
                return
                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

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

