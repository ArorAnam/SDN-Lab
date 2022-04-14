from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def treeTopo():
    net = Mininet( controller=RemoteController,
                    link=TCLink, listenPort=OF_MISC['switch_debug_port']
                    )

    info( '*** Adding controller\n' )
    net.addController('c0')

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', ip='10.0.0.1', mac='00:00:00:00:00:01' )
    h2 = net.addHost( 'h2', ip='10.0.0.2', mac='00:00:00:00:00:02' )
    h3 = net.addHost( 'h3', ip='10.0.0.3', mac='00:00:00:00:00:03' )
    h4 = net.addHost( 'h4', ip='10.0.0.4', mac='00:00:00:00:00:04' )

    info( '*** Adding switches\n' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )

    info( '*** Creating links\n' )
    net.addLink( h1, s1 ) # bandwidth (in Mb/s) and delay can be added as follows
    # net.addLink( h1, s1 ,bw=50,delay=10ms)
    net.addLink( h2, s1 )
    net.addLink( h3, s2 )
    net.addLink( h4, s2 )

    root = s1
    layer1 = [s2,s3]

    for idx,l1 in enumerate(layer1):
        net.addLink( root,l1 )

    info( '*** Starting network\n')

    ################################# this part up to here creates the mininet topology
    net.start() # this commands darts the topology in mininet

    info( '*** Running CLI\n' )
    CLI( net ) # this command creates the mininet prompt, so that now we can interact with
    #mininet through the same terminal (or link from an external controller).

    info( '*** Stopping network' )
    net.stop() # this command is invoked after we enter the exit command in the mininet prompt


if __name__ == '__main__':
    setLogLevel( 'info' )
    treeTopo()
