from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr

TIME_OUT = 60
table={}
log = core.getLogger()

rules = ['00:00:00:00:00:01','00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']

def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp ( event ):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)


def _handle_PacketIn ( event):
    dpid = event.connection.dpid
    sw=dpidToStr(event.dpid)
    inport = event.port
    packet = event.parsed
    print("Event: switch %s port %s packet %s" % (sw, inport, packet))
    # Learn the source
    table[(event.connection,packet.src)] = event.port
    dst_port = table.get((event.connection,packet.dst))

    ################### LOGIC IMPLEMENTED ##################

    # Check for ARP packet
    if packet.type == eth.ARP_TYPE:

        if dst_port is None:
            msg = of.ofp_packet_out(data = event.ofp)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
            event.connection.send(msg)
        else:
            msg = of.ofp_flow_mod()
            msg.priority=100
            msg.match.dl_type = 0x0806
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.hard_timeout = TIME_OUT
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

            msg = of.ofp_packet_out()
            msg.priority=100
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port = dst_port))
            event.connection.send(msg)

            log.debug("Installing %s <-> %s" % (packet.src, packet.dst))

    # else IP packet
    elif packet.type == eth.IP_TYPE:
        ip_packet = packet.payload

        # Check if ICMP pacKET
        if (ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL):

            if dst_port is None:
                msg = of.ofp_packet_out(data = event.ofp)
                msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                event.connection.send(msg)
            else:
                msg = of.ofp_flow_mod()
                msg.priority=100
                msg.match.dl_type = 0x0800
                msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
                msg.match.dl_dst = packet.src
                msg.match.dl_src = packet.dst
                msg.hard_timeout = TIME_OUT
                msg.actions.append(of.ofp_action_output(port = event.port))
                event.connection.send(msg)

                msg = of.ofp_packet_out()
                msg.priority=100
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port = dst_port))
                event.connection.send(msg)

        # TCP packet
        elif (ip_packet.protocol == pkt.ipv4.TCP_PROTOCOL):
            tcp_packet = ip_packet.payload
            src = tcp_packet.srcport
            dest = tcp_packet.dstport
            # rule = (packet.src, packet.dst, src port, dst port)
            if (src == 22 and dest == 22 and packet.src == rules[0] and packet.dst == rules[1]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 22
                    msg.match.tp_dst = 22
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)
            elif (src == 22 and dest == 22 and packet.src == rules[1] and packet.dst == rules[0]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 22
                    msg.match.tp_dst = 22
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)

            # H1, H2 -> H3
            elif (src == 80 and packet.src == rules[0] and packet.dst == rules[2]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 80
                    msg.match.tp_dst = 80
                    msg.hard_timeout = TIME_OUT
                    # msg.actions.append(of.ofp_action_output(port = event.port))
                    msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 0))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    # msg.actions.append(of.ofp_action_output(port = dst_port))
                    msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 0))
                    event.connection.send(msg)
            elif (src == 80 and packet.src == rules[1] and packet.dst == rules[2]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 80
                    msg.match.tp_dst = 80
                    msg.hard_timeout = TIME_OUT
                    # msg.actions.append(of.ofp_action_output(port = event.port))
                    msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 1))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    # msg.actions.append(of.ofp_action_output(port = dst_port))
                    msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 1))
                    event.connection.send(msg)

            # H2 <-> H4
            elif (src == 3000 and dest == 3000 and packet.src == rules[1] and packet.dst == rules[3]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 3000
                    msg.match.tp_dst = 3000
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)
            elif (src == 3000 and dest == 3000 and packet.src == rules[3] and packet.dst == rules[1]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 3000
                    msg.match.tp_dst = 3000
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)

        # UDP packet
        elif (ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL):
            udp_packet = ip_packet.payload
            src = udp_packet.srcport
            dest = udp_packet.dstport
            # rule = (packet.src, packet.dst, src port, dst port)
            if (src == 22 and dest == 22 and packet.src == rules[0] and packet.dst == rules[1]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 22
                    msg.match.tp_dst = 22
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)
            elif (src == 22 and dest == 22 and packet.src == rules[1] and packet.dst == rules[0]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 22
                    msg.match.tp_dst = 22
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)

            # H1, H2 -> H3
            elif (src == 80 and packet.src == rules[0] and packet.dst == rules[2]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 80
                    msg.match.tp_dst = 80
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    # msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 0))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    # msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 0))
                    event.connection.send(msg)
            elif (src == 80 and packet.src == rules[1] and packet.dst == rules[2]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 80
                    msg.match.tp_dst = 80
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    # msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 1))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    # msg.actions.append(of.ofp_action_enqueue(port = dst_port, queue_id = 1))
                    event.connection.send(msg)

            # H2 <-> H4
            elif (src == 6000 and dest == 6000 and packet.src == rules[1] and packet.dst == rules[3]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 6000
                    msg.match.tp_dst = 6000
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)
            elif (src == 6000 and dest == 6000 and packet.src == rules[3] and packet.dst == rules[1]):

                if dst_port is None:
                    msg = of.ofp_packet_out(data = event.ofp)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                    event.connection.send(msg)
                else:
                    msg = of.ofp_flow_mod()
                    msg.priority=100
                    msg.match.dl_type = packet.type
                    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.match.tp_src = 6000
                    msg.match.tp_dst = 6000
                    msg.hard_timeout = TIME_OUT
                    msg.actions.append(of.ofp_action_output(port = event.port))
                    event.connection.send(msg)

                    msg = of.ofp_packet_out()
                    msg.priority=100
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(msg)

    else :
        # We must drop incoming packet...
        msg = of.ofp_flow_mod()
        msg.priority=100
        msg.match.dl_type = packet.type
        # msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.hard_timeout = TIME_OUT
        msg.actions.append(of.ofp_action_output(port = event.port))
        event.connection.send(msg)

        msg = of.ofp_packet_out()
        msg.priority=100
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        event.connection.send(msg)

        log.debug("Dropping %s <-> %s" % (packet.src, packet.dst))
