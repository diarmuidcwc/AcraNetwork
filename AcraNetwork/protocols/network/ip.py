import struct
import socket
import importlib
from AcraNetwork.protocols.network.BasePacket import BasePacket
from AcraNetwork.protocols.network.IpAddress import IpAddress

class IP(BasePacket):
    '''Create or unpack an IP packet'''
    PROTOCOLS = {"ICMP":0x01,"IGMP" : 0X02, "TCP":0x6,"UDP":0x11}
    
    CALC_HEADER = '>BBHHBBBBHII'
    BASETYPE_MAPPING = 'protocol'
    
    TYPE = {
        0x01: {'from': 'AcraNetwork.protocols.network.icmp', 'import': 'ICMP'},
        0x02: {'from': None, 'import': 'IGMP'},
        0x06: {'from': 'AcraNetwork.protocols.network.tcp', 'import': 'TCP'},
        0x11: {'from': 'AcraNetwork.protocols.network.udp', 'import': 'UDP'},
        }
    
    HEADER = [
        {'n': 'reserved0', 'w': 'B', 'd': 0},
        {'n': 'dscp', 'w': 'B', 'd': 0},
        {'n': 'len', 'w': 'H', 'd': 0},
        {'n': 'id', 'w': 'H', 'd': 0},
        {'n': 'flags', 'w': 'B', 'd': 0},
        {'n': 'reserved1', 'w': 'B', 'd': 0},
        {'n': 'ttl', 'w': 'B', 'd': 0},
        {'n': 'protocol', 'w': 'B', 'd': PROTOCOLS['UDP']},
        {'n': 'checksum', 'w': 'H', 'd': 0},
        {'n': 'srcip', 'w': 'I', 'd': 0, 'c': IpAddress()},
        {'n': 'dstip', 'w': 'I', 'd': 0, 'c': IpAddress()},
        ]
    
    def unpack_local(self, buf):
        super(self.__class__, self).unpack_local(buf)
        self.flags = self.flags >> 5
#         self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
#         self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
#         
#     def pack(self):
# #         if isinstance(self.srcip, str):
# #             (srcip_as_int,) = struct.unpack('!I',socket.inet_aton(self.srcip))
# #             self.srcip = srcip_as_int
# #         if isinstance(self.dstip, str):
# #             (dstip_as_int,) = struct.unpack('!I',socket.inet_aton(self.dstip))
# #             self.dstip = dstip_as_int
#         #return super(self.__class__, self, self).pack()
#         pack = super(IP, self).pack()
# #         self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
# #         self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
#         return pack
#    
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
