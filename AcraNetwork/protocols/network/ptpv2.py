from AcraNetwork.protocols.network.BasePacket import BasePacket

class PTPv2(BasePacket):
    '''Class to build and unpack a PTPv2 packet'''
    HEADER = [
        {'n': 'messageId', 'w': 'B'},
        {'n': 'versionPTP', 'w': 'B'},
        {'n': 'messageLength', 'w': 'H'},
        {'n': 'subdomainNumber', 'w': 'B'},
        {'n': 'reserved0', 'w': 's'},
        {'n': 'flags', 'w': 'H'},
        {'n': 'correction', 'w': 'Q'},
        {'n': 'reserved1', 'w': '4s'},
        {'n': 'ClockIdentity', 'w': 'Q'},
        {'n': 'sourcePortId', 'w': 'H'},
        {'n': 'sequenceId', 'w': 'H'},
        {'n': 'control', 'w': 'B'},
        {'n': 'logMessagePeriod', 'w': 'B'},
        ]

    SYNC_HEADER = [
        {'n': 'originTimestamp_s', 'w': ['H', 'I']},
        {'n': 'originTimestamp_ns', 'w': 'I'},
        ]
    
    DELAY_REQ_HEADER = [
        {'n': 'originTimestamp_s', 'w': ['H', 'I']},
        {'n': 'originTimestamp_ns', 'w': 'I'},
        ]
    
    FOLLOW_UP_HEADER = [
        {'n': 'preciseOriginTimestamp_s', 'w': ['H', 'I']},
        {'n': 'preciseOriginTimestamp_ns', 'w': 'I'},
        ]

    DELAY_RESP_HEADER = [
        {'n': 'receiveTimestamp_s', 'w': ['H', 'I']},
        {'n': 'receiveTimestamp_ns', 'w': 'I'},
        {'n': 'requestingSourcePortIdentity', 'w': 'Q'},
        {'n': 'requestingSourcePortId', 'w': 'H'},
        ]

    ANNOUNCE_HEADER = [
        {'n': 'originTimestamp_s', 'w': ['H', 'I']},
        {'n': 'originTimestamp_ns', 'w': 'I'},
        {'n': 'originCurrentUTCOffset', 'w': 'H'},
        {'n': 'reserved2', 'w': 's'},
        {'n': 'priority1', 'w': 'B'},
        {'n': 'grandmasterClockClass', 'w': 'B'},
        {'n': 'grandmasterClockAccuracy', 'w': 'B'},
        {'n': 'grandmasterClockVariance', 'w': 'H'},
        {'n': 'priority2', 'w': 'B'},
        {'n': 'grandmasterClockIdentity', 'w': 'Q'},
        {'n': 'localStepsRemoved', 'w': 'H'},
        {'n': 'TimeSource', 'w': 'B'},
        ]
   
    def unpack_local(self, buf):
        if not '>BBHBsHQ4sQHHBB' == self.HEADER_FORMAT:
            print(self.HEADER_FORMAT)
            raise ValueError("Incorrect format generated {}".format(HEADER_FORMAT))
        
        if 0x0 == self.messageId:
            print('Sync Message')
            self.unpack(buf, self.SYNC_HEADER)
            #print(self.HEADER_FORMAT)
        elif 0x1 == self.messageId:
            print('Delay_Req Message')
            self.unpack(buf, self.DELAY_REQ_HEADER)
            print(self.HEADER_FORMAT)
        elif 0x8 == self.messageId:
            print('Follow_up Message')
            self.unpack(buf, self.FOLLOW_UP_HEADER)
        elif 0x9 == self.messageId:
            print('Delay_Resp Message')
            self.unpack(buf, self.DELAY_RESP_HEADER)
        elif 0xb == self.messageId:
            print('Announce Message')
            self.unpack(buf, self.ANNOUNCE_HEADER)
        else:
            raise ValueError("Unsupported PTP mesage, 0x{0:02x}".format(self.control))
