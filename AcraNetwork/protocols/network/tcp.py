import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket

class TCP(BasePacket):
    '''
    Class to build and unpack a TCP packet
    '''
    PAYLOAD_REQUIRED = False
    HEADER = [
        {'n': 'src', 'w': 'H'},
        {'n': 'dst', 'w': 'H'},
        {'n': 'sequence', 'w': 'I'},
        {'n': 'acknowledge', 'w': 'I'},
        {'n': 'flags', 'w': 'H'}, # FIXME
        {'n': 'window', 'w': 'H'},
        {'n': 'checksum', 'w': 'H'},
        {'n': 'urgentptr', 'w': 'H'},
#         {'n': 'FIXME', 'w': '12s'},
        ]

#     def __init__(self, buf=None):
#         super(self.__class__, self).__init__(buf, debug=True)
    
    def __str__(self):
        baselen = 0
        s = 'TCP\t{}->{} [SYN] Seq={} Win={} Len={} MSS={} WS={} SACK_PERM={}'.format(
            self.src,
            self.dst,
            self.sequence,
            self.window,
            baselen,
            0,
            0,
            0,
            )
        return s
