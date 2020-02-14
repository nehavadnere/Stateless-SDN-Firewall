from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
log = core.getLogger()

class L4Firewall(object):

  def __init__ (self, connection, fwconfig):
 
    self.connection = connection
    self.macToPort = {}
    connection.addListeners(self)
    self.fwconfig = fwconfig
 
  def replyToARP(self, packet, match, event):

    r = arp()
    r.opcode = arp.REPLY
    r.hwdst = match.dl_src
    r.protosrc = match.nw_dst
    r.protodst = match.nw_src
    r.hwsrc = match.dl_dst
    e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    msg.in_port = event.port
    event.connection.send(msg) 
    #print(r.protosrc, r.protodst)
 
  def installFlow(self, srcip, dstip):

    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = IPAddr(srcip)
    match.nw_dst = IPAddr(dstip)
    match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
    match.dl_type = pkt.ethernet.IP_TYPE
    msg.match = match
    msg.hard_timeout = 0
    msg.idle_timeout = 200
    msg.priority = 50000
    action = of.ofp_action_output(port = of.OFPP_NORMAL)
    msg.actions.append(action)
    self.connection.send(msg)
  
  def replyToIP(self, packet, match, event, fwconfig):

    srcip = str(match.nw_src)
    dstip = str(match.nw_dst)

    for rule in fwconfig:      
        if ((rule[0] == srcip and rule[1] ==dstip) or (rule[0]==dstip and rule[1]==srcip)):
         print(srcip, dstip)  
         self.installFlow(srcip, dstip)

  def _handle_PacketIn(self, event):
 
    packet = event.parsed
    match = of.ofp_match.from_packet(packet)
    
    if(match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):

      self.replyToARP(packet, match, event)

    if(match.dl_type == packet.IP_TYPE):

      self.replyToIP(packet, match, event, self.fwconfig)     
 
class learning(object):

  def __init__(self, config):
    core.openflow.addListeners(self)
 
    self.fwconfig = list()
    config = "l3firewall.config"
    fin = open(config)

    for line in fin:
      rule = line.split()
      if(len(rule)>0):
        self.fwconfig.append(rule)
        
  def _handle_ConnectionUp(self, event):
    log.debug("Connection %s" % (event.connection,))
    L4Firewall(event.connection, self.fwconfig)
 
def launch(config=""):

  core.registerNew(learning, config)



