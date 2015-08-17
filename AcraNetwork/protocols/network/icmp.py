from copy import copy
from AcraNetwork.protocols.network.BasePacket import BasePacket

class ICMP(BasePacket):
    '''Create or unpack an ICMP packet'''
    BASE_HEADER = [
        {'n': 'type', 'w': 'B'},
        {'n': 'code', 'w': 'B'},
        {'n': 'checksum', 'w': 'H'},
        {'n': 'identifier_be', 'w': 'H'},
        {'n': 'identifier_le', 'w': 'H'},
        {'n': 'timestamp', 'w': 'Q'},
        #{'n': 'data', 'w': '48s'},
        ]
    
    def __init__(self, buf=None, payload_length=None):
        self.HEADER = copy(self.BASE_HEADER)
        if not None == payload_length:
            data_width = payload_length-36
            self.HEADER.append({'n': 'data', 'w': '{:d}s'.format(data_width)})
        super(ICMP, self).__init__(buf)
