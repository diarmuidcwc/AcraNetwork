import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket

class IPv6(BasePacket):
    '''Create or unpack an IPv6 packet'''
    
    HEADER = [
        {'n': 'version_traffic', 'w': 'I'},
        {'n': 'payload_length', 'w': 'H'},
        {'n': 'next_header', 'w': 'B'},
        {'n': 'hop_limit', 'w': 'B'},
        {'n': 'src', 'w': ['Q', 'Q']},
        {'n': 'dst', 'w': ['Q', 'Q']},
        ]
    
    def unpack_local(self, buf):
        #print(self.HEADER_FORMAT)
        #self.traffic_class = self.version_traffic  & 0xf
        #print("0x{:016x}".format(self.src))
        #print("0x{:016x}".format(self.dst))
        if not '>IHBBQQQQ' == self.HEADER_FORMAT:
            raise ValueError("Incorrect format generated {}".format(HEADER_FORMAT))
        self.version       = (self.version_traffic >> 28) & 0xf
        #print(self.version)
