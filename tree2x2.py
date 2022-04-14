from mininet.net import Mininet
# →Import the Mininet library

from mininet.topolib import TreeTopo
# →Import the topology library

tree4 = TreeTopo(depth=2,fanout=2)
# →Create a tree topology with the TreeTopo API

net = Mininet(topo=tree4)
# →Create a handle to the mininet sim with the topology above

net.start()
# →Start Mininet

h1, h4 = net.hosts[0], net.hosts[3]
# →Assign to variables h1 and h4 the hosts number 0 and 3

# print(h1.cmd('ping -c1 %s' % h4.IP()))
#→Run the ping command from h1 to h4 and print the results

# print(h1.cmd("python -m http.server 80 >& /tmp/http.log &"))
# print(h4.cmd('wget -o - %s'% h1.IP()))

h1.cmd('iperf -s &')
print(h4.cmd('iperf -c %s' % h1.IP()))

net.stop()
# →Stop Mininet
