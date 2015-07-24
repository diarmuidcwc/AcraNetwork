import struct
from AcraNetwork.protocols.network.BasePacket import BasePacket, MACAddress

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

    def __str__(self):
        s = 'TTE PCF\tSync Domain: 0x{:02x} Sync Priority 0x{:02x}'.format(
            self.sync_domain,
            self.sync_priority,
            )
        return s
    
    def sprint(self):
        dst = self.parent.dstmac
        src = self.parent.srcmac
        s = [
            'TTEthernet',
            '  Destination: {}'.format(dst),
            '  Source: {}'.format(src),
            '  Type: TTEthernet Protocol Control Frame (0x891d)',
            'TTEthernet Protocol Control Frame',
            '  Integration Cycle: 0x{:08x}'.format(self.integration_cycle),
            '  Membership New: 0x{:08x}'.format(self.membership_new),
            '  Sync Priority: 0x{:02x}'.format(self.sync_priority),
            '  Sync Domain: 0x{:02x}'.format(self.sync_domain),
            '  ... {0:04b} = Type: {1} (0x{0:02x})'.format(self.type, self.type_text),
            '  Transparent Clock: 0x{:016x}'.format(self.transparent_clock),
            ]
        return "\n".join(s)
