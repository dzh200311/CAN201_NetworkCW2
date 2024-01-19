from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm


def myTopo():
    net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24')

    client1 = net.addHost('client1', cls=Host, defaultRoute=None)
    server1 = net.addHost('server1', cls=Host, defaultRoute=None)
    server2 = net.addHost('server2', cls=Host, defaultRoute=None)
    switch1 = net.addSwitch('switch1', cls=OVSKernelSwitch, failMode='secure')
    sdn_controller = net.addController('controller', RemoteController)

    net.addLink(client1, switch1)
    net.addLink(server1, switch1)
    net.addLink(server2, switch1)

    net.build()
    net.start()

    client1.setMAC(intf="client1-eth0", mac="00:00:00:00:00:03")
    server1.setMAC(intf="server1-eth0", mac="00:00:00:00:00:01")
    server2.setMAC(intf="server2-eth0", mac="00:00:00:00:00:02")

    client1.setIP(intf="client1-eth0", ip='10.0.1.5/24')
    server1.setIP(intf="server1-eth0", ip='10.0.1.2/24')
    server2.setIP(intf="server2-eth0", ip='10.0.1.3/24')

    net.terms += makeTerm(sdn_controller)
    net.terms += makeTerm(switch1)
    net.terms += makeTerm(client1)
    net.terms += makeTerm(server1)
    net.terms += makeTerm(server2)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myTopo()