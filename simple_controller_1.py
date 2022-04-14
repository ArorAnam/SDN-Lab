from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr

log = core.getLogger()
table={}

def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp ( event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)

    for rule in rules:
        block = of.ofp_match()
        block.dl_src = EthAddr(rule[0])
        block.dl_dst = EthAddr(rule[1])
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 32000
        event.connection.send(flow_mod)

def _handle_PacketIn ( event):
    dpid = event.connection.dpid
    sw=dpidToStr(event.dpid)
    inport = event.port
    packet = event.parsed
    print("Event: switch %s port %s packet %s" % (sw, inport, packet))

    # Learn the source
    table[(event.connection,packet.src)] = event.port

    dst_port = table.get((event.connection,packet.dst))

    if dst_port is None:
        # This must be an ARP request, so we send it out all ports.
        # We could use either of the special ports OFPP_FLOOD or OFP_ALL.
        # But not all switches support OFPP_FLOOD.
        msg = of.ofp_packet_out(data = event.ofp)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        event.connection.send(msg)
    else:
        # This must be a non-ARP request, we install forward rule spec to source and dest MAC’s
        msg = of.ofp_flow_mod()
        msg.priority=100
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.actions.append(of.ofp_action_output(port = event.port))
        event.connection.send(msg)

        # We must forward the incoming packet...
        msg = of.ofp_packet_out()
        msg.priority=100
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = dst_port))
        event.connection.send(msg)

        log.debug("Installing %s <-> %s" % (packet.src, packet.dst))

rules=[['00:00:00:00:00:01','00:00:00:00:00:02'],['00:00:00:00:00:03', '00:00:00:00:00:04']]


def check_rule (packet):

    src = packet.src
    dst = packet.dst

    rule_list = [   (rules[2], rules[3]),
                    (rules[0], rules[3]),
                    (rules[0], rules[1]),
                    (rules[1], rules[3]),
                    (rules[1], rules[2]),
                    (rules[0], rules[2])
                ]


# def firewall_check( event, dst_port ):
#
#     dpid = event.connection.dpid
#     sw=dpidToStr(event.dpid)
#     inport = event.port
#     packet = event.parsed
#
#
#     # For H1, H2
#     if 'tcp' or 'udp' in packet:
#         msg =
#         if in_port == tp_src(22) and dst_port == tp_dst():
#             return True
