import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket

class UDP(BasePacket):
    '''Class to build and unpack a UDP packet'''
    BASETYPE_MAPPING = 'dstport'
    
    TYPE = {
        0x013f: {'from': 'AcraNetwork.protocols.network.ptp', 'import': 'PTP'},
        0x0140: {'from': 'AcraNetwork.protocols.network.ptp', 'import': 'PTP'},
        0x0089: {'from': None, 'import': 'netbios-ns'},
        0x008a: {'from': None, 'import': 'netbios-dgm'},
        0x03ff: {'from': 'AcraNetwork.protocols.network.inetx', 'import': 'iNetX'},
        0x0400: {'from': 'AcraNetwork.protocols.network.iena', 'import': 'IENA'},
        0x079b: {'from': None, 'import': 'sentialsrm'},
        0x14eb: {'from': None, 'import': 'llmnr'},
        0x14e9: {'from': None, 'import': 'mdns'},
        0x076c: {'from': None, 'import': 'ssdp'},
        0x5208: {'from': None, 'import': 'Unknown'},
        }
    HEADER = [
        {'n': 'srcport', 'w': 'H'},
        {'n': 'dstport', 'w': 'H'},
        {'n': 'len', 'w': 'H'},
        {'n': 'checksum', 'w': 'H'},
        ]
    
#     def unpack_local(self, buf):
#         super(self.__class__, self).unpack_local(buf)
#         self.assign_packet()
# 
    def pack(self):
        if None == self.payload:
            raise ValueError("Unpopulated payload")
        
        self.len = len(self.payload) + self.HEADER_SIZE
        return super(UDP, self).pack()
