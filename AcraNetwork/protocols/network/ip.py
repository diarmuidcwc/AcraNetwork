import struct
import socket
from AcraNetwork.protocols.network.icmp import ICMP
from AcraNetwork.protocols.network.udp import UDP
from AcraNetwork.protocols.network.BasePacket import BasePacket

class IP(BasePacket):
    '''Create or unpack an IP packet'''
    PROTOCOLS = {"ICMP":0x01,"IGMP" : 0X02, "TCP":0x6,"UDP":0x11}
    #IP_HEADER_FORMAT = '>BBHHBBBBHII'
    #IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)
    
    HEADER = [
        {'n': 'reserved0', 'w': 'B'},
        {'n': 'dscp', 'w': 'B'},
        {'n': 'len', 'w': 'H'},
        {'n': 'id', 'w': 'H'},
        {'n': 'flags', 'w': 'B'},
        {'n': 'reserved1', 'w': 'B'},
        {'n': 'ttl', 'w': 'B'},
        {'n': 'protocol', 'w': 'B', 'd': PROTOCOLS['UDP']},
        {'n': 'checksum', 'w': 'H'},
        {'n': 'srcip', 'w': 'I'},
        {'n': 'dstip', 'w': 'I'},
        ]
    
    def unpack_local(self, buf):
        print(self.HEADER_FORMAT)
        if not '>BBHHBBBBHII' == self.HEADER_FORMAT:
            raise ValueError("Incorrect format generated {}".format(self.HEADER_FORMAT))

        self.flags = self.flags >> 5
        self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
        self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))

        if   0x01 == self.protocol:
            print("ICMP")
            self.icmp = ICMP(self.payload, self.len)
            #exit()
        elif 0x02 == self.protocol:
            print("IGMP")
        elif 0x06 == self.protocol:
            print("TCP")
        elif 0x11 == self.protocol:
            print("UDP")
            self.udp = UDP(self.payload)
        else:
            raise ValueError("Unsupported IP Protocol, 0x{0:02x}".format(self.protocol))
    
#     def __init__(self,buf=None):
#         self.srcip = None
#         """:type str"""
#         self.dstip = None
#         """:type str"""
#         self.len = None
#         """:type int"""
#         self.flags = 0x0
#         """:type int"""
#         self.protocol = IP.PROTOCOLS['UDP'] # default to udp
#         """:type int"""
#         self.payload = None
#         """:type str"""
#         self.version = 4 # IPV4
#         """:type int"""
#         self.ihl = 5 # Header len in 32 bit words
#         """:type int"""
#         self.dscp = 0
#         """:type int"""
#         self.id = 0
#         """:type int"""
#         self.ttl = 20
#         """:type int"""
#         if buf != None:
#             self.unpack(buf)
# 
#     def unpack(self,buf):
#         '''Unpack a buffer into an ethernet object'''
# 
#         if len(buf) < IP.IP_HEADER_SIZE:
#             raise ValueError("Buffer too short for to be an IP packet")
#         (na1,self.dscp, self.len,self.id,self.flags,na3, self.ttl, self.protocol, checksum, self.srcip,self.dstip) = struct.unpack_from(IP.IP_HEADER_FORMAT,buf)
#         self.flags = self.flags >> 5
#         #self.version = na1 >>4
#         #self.ihl = na1 & 0xf
#         self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
#         self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
#         self.payload = buf[IP.IP_HEADER_SIZE:]
#         if   0x01 == self.protocol:
#             print("ICMP")
#         elif 0x02 == self.protocol:
#             print("IGMP")
#         elif 0x06 == self.protocol:
#             print("TCP")
#         elif 0x11 == self.protocol:
#             print("UDP")
#             self.udp = UDP(self.payload)
#         else:
#             raise ValueError("Unsupported IP Protocol, 0x{0:02x}".format(self.protocol))
#         
# 
#     def pack(self):
#         '''Pack the IP object into a string buffer
#         :rtype :str
#         '''
#         for word in [self.dscp,self.id,self.flags,self.ttl,self.protocol,self.srcip,self.dstip]:
#             if word == None:
#                 raise ValueError("All required IP payloads not defined")
# 
#         (srcip_as_int,) = struct.unpack('!I',socket.inet_aton(self.srcip))
#         (dstip_as_int,) = struct.unpack('!I',socket.inet_aton(self.dstip))
#         self.len = IP.IP_HEADER_SIZE+len(self.payload)
#         header = struct.pack(IP.IP_HEADER_FORMAT,0x45,self.dscp,self.len,self.id,self.flags,0,self.ttl,self.protocol,0,srcip_as_int,dstip_as_int)
#         checksum = calc_checksum(header)
#         header = header[:10] + struct.pack('H',checksum) + header[12:]
#         return header + self.payload
