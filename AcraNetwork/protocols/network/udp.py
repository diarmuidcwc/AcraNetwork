import struct
from AcraNetwork.protocols.network.ptp import PTP
from AcraNetwork.protocols.network.BasePacket import BasePacket

class UDP(BasePacket):
    '''Class to build and unpack a UDP packet'''
    HEADER = [
        {'n': 'srcport', 'w': 'H'},
        {'n': 'dstport', 'w': 'H'},
        {'n': 'len', 'w': 'H'},
        {'n': 'checksum', 'w': 'H'},
        ]
    
    def unpack_local(self, buf):
        if   0x013f == self.dstport:
            print("ptp-event")
            self.ptp = PTP(self.payload)
        elif 0x0140 == self.dstport:
            print("ptp-general")
            self.ptp = PTP(self.payload)
        elif 0x0089 == self.dstport:
            print("netbios-ns")
        elif 0x008a == self.dstport:
            print("netbios-dgm")
        elif 0x079b == self.dstport:
            print("sentialsrm")
        elif 0x14eb == self.dstport:
            print("llmnr")
        elif 0x14e9 == self.dstport:
            print("mdns")
        elif 0x076c == self.dstport:
            print("ssdp")
        else:
            raise ValueError("Unsupported UDP Protocol, 0x{0:02x}".format(self.dstport))
# 
#     def pack(self):
#         '''Pack a UDP object into a buffer
#         :rtype :str
#         '''
#         if self.srcport == None or self.dstport == None or self.payload == None:
#             raise ValueError("All UDP fields need to be defined to pack the payload")
# 
#         self.len = len(self.payload) + UDP.UDP_HEADER_SIZE
#         return struct.pack(UDP.UDP_HEADER_FORMAT,self.srcport,self.dstport,self.len,0) + self.payload
