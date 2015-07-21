class AFDX():
    '''This class will  unpack an AFDX packet'''
    HEADERLEN = 14
    DSTMAC_CONST = 0x3000000
    SRCMAC_CONST = 0x20000
    MIN_PAYLOAD_LEN = 42
    def __init__(self,buf=None):
        self.type =None
        self.networkID = None
        self.equipmentID = None
        self.interfaceID = None
        self.vlink = None

        self.payload = None
        self.sequencenum = None
        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        self.set_dstmac(buf[:6])
        self.unpacksrcmac(unpack48(buf[6:12]))

        (self.type,) = struct.unpack_from('>H',buf,12)
        self.payload = buf[AFDX.HEADERLEN:-1]
        self.sequencenum = struct.unpack('B',buf[-1])

    def unpacksrcmac(self,mac):
        srcconstantf = mac >> 24
        #if srcconstantf != AFDX.SRCMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in SrcMac Address'.format(AFDX.SRCMAC_CONST))
        #(self.networkID,self.equipmentID,self.interfaceID) = struct.unpack_from('BBB',mac[:3])
        #self.interfaceID = self.interfaceID >> 5

    def set_dstmac(self,mac):
        (dstconstantf,vlink) = struct.unpack_from('>IH',mac)
        #if dstconstantf != AFDX.DSTMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in DestMac Address'.format(AFDX.DSTMAC_CONST))
        self.vlink = vlink

    def pack(self):

        if (len(self.payload) < AFDX.MIN_PAYLOAD_LEN):
            raise ValueError('Minimum Payload of {} bytes'.format(AFDX.MIN_PAYLOAD_LEN))

        afdx_header = struct.pack('>IHHBBBBH',AFDX.DSTMAC_CONST,self.vlink,(AFDX.SRCMAC_CONST>>8),0,self.networkID,self.equipmentID,(self.interfaceID<<5),self.type)
        packet = afdx_header + self.payload + struct.pack('>B',self.sequencenum)

        return packet


