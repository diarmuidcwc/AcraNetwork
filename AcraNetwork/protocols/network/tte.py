import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket

class TTE(BasePacket):
    '''Create or unpack an TTE packet'''
    CALC_HEADER = '>II4sBBB5sQ18s'
    
    PROTOCOLS = {
        0x2: 'integration frame',
        0x4: 'coldstart frame',
        0x8: 'coldstart ack frame',
        }
    HEADER = [
        {'n': 'integration_cycle', 'w': 'I'},
        {'n': 'membership_new', 'w': 'I'},
        {'n': 'reserved0', 'w': '4s'},
        {'n': 'sync_priority', 'w': 'B'},
        {'n': 'sync_domain', 'w': 'B'},
        {'n': 'type', 'w': 'B'},
        {'n': 'reserved1', 'w': '5s'},
        {'n': 'transparent_clock', 'w': 'Q'},
        {'n': 'reserved2', 'w': '18s'},
        ]
    
    def unpack_local(self, buf):
        super(self.__class__, self).unpack_local(buf)
        if not self.type in self.PROTOCOLS.keys():
            raise ValueError("Unknown frame type {}".format(self.type))
        self.type_text = self.PROTOCOLS[self.type]
