from AcraNetwork.protocols.network.BasePacket import BasePacket

class PTPv1(BasePacket):
    '''Class to build and unpack a PTPv1 packet'''
    HEADER = [
        {'n': 'versionPTP', 'w': 'H'},
        {'n': 'versionNetwork', 'w': 'H'},
        {'n': 'subdomain', 'w': '16s', 'd': b'_DFLT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'},
        {'n': 'messageType', 'w': 'B'},
        {'n': 'sourceCommunicationTechnology', 'w': 'B'},
        {'n': 'sourceUuid', 'w': ['H', 'I']},
        {'n': 'sourcePortId', 'w': 'H'},
        {'n': 'sequenceId', 'w': 'H'},
        {'n': 'control', 'w': 'B'},
        {'n': 'reserved0', 'w': 's'},
        {'n': 'flags', 'w': 'H'},
        ]
     
    SYNC_HEADER = [
        {'n': 'reserved1', 'w': '4s'},
        {'n': 'originTimestamp_s', 'w': 'I'},
        {'n': 'originTimestamp_ns', 'w': 'I'},
        {'n': 'epochNumber', 'w': 'H'},
        {'n': 'currentUTCOffset', 'w': 'H'},
        {'n': 'reserved2', 'w': 'B'},
        {'n': 'grandMasterCommunicationTechnology', 'w': 'B'},
        {'n': 'grandMasterClockUuid', 'w': ['H', 'I']},
        {'n': 'grandMasterPortId', 'w': 'H'},
        {'n': 'grandMasterSequenceID', 'w': 'H'},
        {'n': 'reserved3', 'w': '3s'},
        {'n': 'grandMasterClockStratum', 'w': 'B'},
        {'n': 'grandMasterClockIdentifier', 'w': '4s'},
        {'n': 'reserved4', 'w': '2s'},
        {'n': 'grandMasterClockVariance', 'w': 'h'},
        {'n': 'reserved5', 'w': 's'},
        {'n': 'grandMasterPreferred', 'w': 'B'},
        {'n': 'reserved6', 'w': 's'},
        {'n': 'grandMasterIsBoundaryClock', 'w': 'B'},
        {'n': 'reserved7', 'w': '3s'},
        {'n': 'syncInterval', 'w': 'B'},
        {'n': 'reserved8', 'w': '2s'},
        {'n': 'localClockVariance', 'w': 'H'},
        {'n': 'reserved9', 'w': '2s'},
        {'n': 'localStepsRemoved', 'w': 'H'},
        {'n': 'reserved10', 'w': '3s'},
        {'n': 'localClockStratum', 'w': 'B'},
        {'n': 'localClockIdentifer', 'w': '4s'},
        {'n': 'reserved11', 'w': 's'},
        {'n': 'parentCommunicationTechnology', 'w': 'B'},
        {'n': 'parentUuid', 'w': ['H', 'I']},
        {'n': 'reserved12', 'w': '2s'},
        {'n': 'parentPortField', 'w': 'H'},
        {'n': 'reserved13', 'w': '2s'},
        {'n': 'esimatedMasterVariance', 'w': 'H'},
        {'n': 'estimatedMasterDrift', 'w': 'H'},
        {'n': 'reserved14', 'w': '3s'},
        {'n': 'utcReasonable', 'w': 'B'},
        ]
    
    FOLLOW_UP_HEADER = [
        {'n': 'reserved1', 'w': '6s'},
        {'n': 'associatedSequenceId', 'w': 'H'},
        {'n': 'preciseOriginTimestamp_s', 'w': 'I'},
        {'n': 'preciseOriginTimestamp_ns', 'w': 'I'},
        ]
   
    def unpack_local(self, buf):
        #print(self.HEADER_FORMAT)
        if not '>HH16sBBHIHHBsH' == self.HEADER_FORMAT:
            raise ValueError("Incorrect format generated {}".format(self.HEADER_FORMAT))
        
        if 0x0 == self.control:
            self.unpack(buf, self.SYNC_HEADER)
        elif 0x2 == self.control:
            self.unpack(buf, self.FOLLOW_UP_HEADER)
            #print(self.HEADER_FORMAT)
            #exit()
        else:
            raise ValueError("Unsupported PTP mesage, 0x{0:02x}".format(self.control))
