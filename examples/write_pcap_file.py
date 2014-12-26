
import time
import struct
import AcraNetwork.IENA as iena
import AcraNetwork.iNetX as inetx
import AcraNetwork.McastSocket as mcast
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet


# constants
PCAP_FNAME = "output_test.pcap"
PACKETS_TO_WRITE = 100

# Write out a pcapfile with each inetx and iena packet generated
mypcap = pcap.Pcap(PCAP_FNAME,forreading=False)
mypcap.writeGlobalHeader()
ethernet_packet = SimpleEthernet.Ethernet()
ethernet_packet.srcmac = 0x001122334455
ethernet_packet.dstmac = 0x554433221100
ip_packet = SimpleEthernet.IP()
ip_packet.dstip = "235.0.0.2"
ip_packet.srcip = "127.0.0.1"
udp_packet = SimpleEthernet.UDP()
udp_packet.dstport = 4422


# Fixed payload for both
payload = struct.pack(">L",5)


# Create an inetx packet
myinetx = inetx.iNetX()
myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
myinetx.pif = 0
myinetx.streamid = 0xdc
myinetx.sequence = 0
myinetx.payload = payload

# Create an iena packet
myiena = iena.IENA()
myiena.key = 0xdc
myiena.keystatus = 0
myiena.endfield = 0xbeef
myiena.sequence = 0
myiena.payload = payload
myiena.status = 0



packets_written = 0

while packets_written < PACKETS_TO_WRITE:

    currenttime = int(time.time())

    myiena.sequence += 1
    myiena.setPacketTime(currenttime)
    udp_packet.payload = myiena.pack()
    udp_packet.srcport = 5000
    ip_packet.payload = udp_packet.pack()
    ethernet_packet.payload = ip_packet.pack()
    mypcap.writeAPacket(ethernet_packet.pack())


    myinetx.sequence += 1
    myinetx.setPacketTime(currenttime)
    udp_packet.payload = myinetx.pack()
    udp_packet.srcport = 5001
    ip_packet.payload = udp_packet.pack()
    ethernet_packet.payload = ip_packet.pack()
    mypcap.writeAPacket(ethernet_packet.pack())

    packets_written += 2

