from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from ryu.lib.packet import ether_types


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        ip6_pkt = pkt.get_protocol(ipv6.ipv6)

        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet-in, dpid=%s src=%s dst=%s in_port=%s", dpid, src, dst, in_port)
        self.logger.info("ipv4: %s, ipv6: %s, tcp: %s", ip4_pkt, ip6_pkt, tcp_pkt)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.

        # FOR ICMP PING
        if not tcp_pkt:

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            # construct action list.
            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time.
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions, idle=5)
            self.logger.info("packet-out, buffer_id=%s, actions=%s \n", ofproto.OFP_NO_BUFFER, actions)
            # construct packet_out message and send it.
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

        # FOR TCP
        else:
            # client to server1  -> redirect -> client to server2
            if dst == "00:00:00:00:00:01" and src == "00:00:00:00:00:03":
                self.logger.info("MATCH! client to server1\n")

                if '00:00:00:00:00:02' in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid]['00:00:00:00:00:02']
                else:
                    out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionSetField(eth_dst='00:00:00:00:00:02'),
                           parser.OFPActionSetField(ipv4_dst='10.0.1.3'),
                           parser.OFPActionOutput(port=out_port)]

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip4_pkt.src,
                                        ipv4_dst=ip4_pkt.dst)
                self.add_flow(datapath, 2, match, actions, idle=5)

                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions,
                                          data=msg.data)
                datapath.send_msg(out)
            # server2 to client -> reply
            elif dst == "00:00:00:00:00:03" and src == "00:00:00:00:00:02":
                self.logger.info("MATCH! server2 to client\n")

                if '00:00:00:00:00:03' in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid]['00:00:00:00:00:03']
                else:
                    out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionSetField(eth_src='00:00:00:00:00:01'),
                           parser.OFPActionSetField(ipv4_src='10.0.1.2'),
                           parser.OFPActionOutput(port=out_port)]

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip4_pkt.src,
                                        ipv4_dst=ip4_pkt.dst)
                self.add_flow(datapath, 2, match, actions, idle=5)

                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions,
                                          data=msg.data)
                datapath.send_msg(out)
            else:
                self.logger.info("ERROR dst:%s, src:%s\n", dst, src)
