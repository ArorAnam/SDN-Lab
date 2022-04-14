rules= ['00:00:00:00:00:01','00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']

rule_list = [   (rules[2], rules[3]),
                (rules[3], rules[2]),
                (rules[0], rules[3]),
                (rules[3], rules[0]),
                (rules[0], rules[1]),
                (rules[1], rules[0]),
                (rules[0], rules[2]),
                (rules[1], rules[2]),
                (rules[2], rules[0]),
                (rules[2], rules[1]),
                (rules[1], rules[3]),
                (rules[3], rules[1])
            ]

rule_list_2 = [ (rules[0], rules[1], 22, 22),
                (rules[1], rules[0], 22, 22)
            ]

def define_rules( event, rule ):

    # Define the firewall rules
    # match rule:
    # Defiune plain block rules
    if rule == (rules[2], rules[3]) or rule == (rules[3], rules[2]):
        # H3 <-> H4
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[2])
        block.dl_dst = EthAddr(rules[3])
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 32000
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

    elif rule == (rules[0], rules[3]) or rule == (rules[3], rules[0]):
        # H1 <-> H4
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[0])
        block.dl_dst = EthAddr(rules[3])
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 32000
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

    elif rule == (rules[0], rules[1]) or rule == (rules[1], rules[0]):
        # H1 <-> H2 Block
        print("\n H1 <-> H2 \n")

        block = of.ofp_match(
                                dl_src = EthAddr(rules[0]),
                                dl_dst = EthAddr(rules[1])
                            )
        # block.dl_type = pkt.ethernet.IP_TYPE
        # block.nw_proto = pkt.ipv4.TCP_PROTOCOL or pkt.ipv4.UDP_PROTOCOL
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 32000
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

        block = of.ofp_match(
                                dl_src = EthAddr(rules[1]),
                                dl_dst = EthAddr(rules[0])
                            )
        # block.dl_type = pkt.ethernet.IP_TYPE
        # block.nw_proto = pkt.ipv4.TCP_PROTOCOL or pkt.ipv4.UDP_PROTOCOL
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 32000
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

    # allow ARP
    # block = of.ofp_match()
    # block.dl_src = EthAddr(rules[0])
    # block.dl_dst = EthAddr(rules[1])
    # block.dl_type = 0x0806
    # # block = not block
    # flow_mod = of.ofp_flow_mod()
    # flow_mod.match = block
    # flow_mod.priority = 100
    # event.connection.send(flow_mod)
    #
    # block = of.ofp_match()
    # block.dl_src = EthAddr(rules[1])
    # block.dl_dst = EthAddr(rules[0])
    # block.dl_type = 0x0806
    # # block = not block
    # flow_mod = of.ofp_flow_mod()
    # flow_mod.match = block
    # flow_mod.priority = 100
    # event.connection.send(flow_mod)


        # only TCP - 22, UDP - 22
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[0])
        block.dl_dst = EthAddr(rules[1])
        block.dl_type = pkt.ethernet.IP_TYPE
        block.nw_proto = pkt.ipv4.TCP_PROTOCOL or pkt.ipv4.UDP_PROTOCOL
        block.tp_src = 22
        block.tp_dst = 22
        # block = not block
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 100
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

        # only TCP - 22, UDP - 22
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[1])
        block.dl_dst = EthAddr(rules[0])
        block.dl_type = pkt.ethernet.IP_TYPE
        block.nw_proto = pkt.ipv4.TCP_PROTOCOL or pkt.ipv4.UDP_PROTOCOL
        block.tp_src = 22
        block.tp_dst = 22
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 100
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

    elif rule == (rules[1], rules[3]):
        # H2 <-> H4
        # only TCP - 3000, UDP - 6000
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[1])
        block.dl_dst = EthAddr(rules[3])
        block.dl_type = pkt.ethernet.IP_TYPE
        if block.nw_proto == pkt.ipv4.TCP_PROTOCOL:
            block.tp_src = 3000
            block.tp_dst = 3000
        elif block.nw_proto == pkt.ipv4.UDP_PROTOCOL:
            block.tp_src = 6000
            block.tp_dst = 6000
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 100
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)

    elif rule == (rules[0], rules[2]) or ruke == (rules[1], rules[2]):
        # H1, H2 -> H3
        block = of.ofp_match()
        block.dl_src = EthAddr(rules[1]) or EthAddr(rules[0])
        block.dl_dst = EthAddr(rules[2])
        block.dl_type = pkt.ethernet.IP_TYPE
        block.nw_proto = pkt.ipv4.TCP_PROTOCOL or pkt.ipv4.UDP_PROTOCOL
        # tp_src = 22
        block.tp_dst = 80
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = block
        flow_mod.priority = 100
        flow_mod.hard_timeout = TIME_OUT
        event.connection.send(flow_mod)
