# import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket

class TTE(BasePacket):
    '''Create or unpack an TTE packet'''
    CALC_HEADER = '>II4sBBB5sQ18s'
    PAYLOAD_REQUIRED = False    
    
    PROTOCOLS = {
        0x0: 'Unknown',
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
     
    @property
    def type_text(self):
        if not self.type in self.PROTOCOLS.keys():
            raise ValueError("Unknown frame type {}".format(self.type))
        return self.PROTOCOLS[self.type]

    @property
    def macdest(self):
        if hasattr(self.parent, 'dstmac'):
            return (self.parent.dstmac.int >> 16 )& 0xffffffff
        else:
            return 0

    @property
    def ctid(self):
        if hasattr(self.parent, 'dstmac'):
            return self.parent.dstmac.int & 0xffff
        else:
            return 0

    def __str__(self):
        s = 'TTE PCF\tSync Domain: 0x{:02x} Sync Priority 0x{:02x}'.format(
            self.sync_domain,
            self.sync_priority,
            )
        return s
    
    def sprint(self):
        s = [
            'TTEthernet',
            '  Destination: {}'.format(self.parent.dstmac),
            '    Constant Field: 0x{:08x}'.format(self.macdest),
            '    Critical Traffic Identifer: 0x{:04x}'.format(self.ctid),
            '  Source: {}'.format(self.parent.srcmac),
            '  Type: TTEthernet Protocol Control Frame (0x{0:04x})'.format(self.parent.type),
            'TTEthernet Protocol Control Frame',
            '  Integration Cycle: 0x{:08x}'.format(self.integration_cycle),
            '  Membership New: 0x{:08x}'.format(self.membership_new),
            '  Sync Priority: 0x{:02x}'.format(self.sync_priority),
            '  Sync Domain: 0x{:02x}'.format(self.sync_domain),
            '  ... {0:04b} = Type: {1} (0x{0:02x})'.format(self.type, self.type_text),
            '  Transparent Clock: 0x{:016x}'.format(self.transparent_clock),
            ]
        return "\n".join(s)
