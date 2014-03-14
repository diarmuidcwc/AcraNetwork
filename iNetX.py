import socket
import struct
import os
from ParserAligned import ParserAlignedPacket as iNetXParser

class iNetX ():
    CONTROLWORD = 0x11000000
    HEADER_LEN = 28
    def __init__(self):
        """Class for generating an iNetX packet. """
        self.inetxcontrol = iNetX.CONTROLWORD
        self.streamid = None
        self.sequence = None
        self.packetlen = None
        self.ptptimeseconds = None
        self.ptptimenanoseconds = None
        self.pif = None
        self.payload = None #string containing payload
        self.bytes = None
        self.packetstrut = struct.Struct('>LLLLLLL')

        self.s = None




    def pack(self):
        '''Pack the packet into a byte  format'''
        self.packetlen =  len(self.payload)  + iNetX.HEADER_LEN
        packetvalues = (self.inetxcontrol,self.streamid,self.sequence,self.packetlen,self.ptptimeseconds,self.ptptimenanoseconds,self.pif )
        self.packet = self.packetstrut.pack(*packetvalues) + self.payload
        self._calcsize()

    def unpack(self,buf,checkcontrol=False):
        '''Unpack a raw byte stream to an iNetX object'''
        self.inetxcontrol,self.streamid,self.sequence,self.packetlen,self.ptptimeseconds,self.ptptimenanoseconds,self.pif  = self.packetstrut.unpack_from(buf)
        self.packetlen = len(buf)
        self.payload = buf[iNetX.HEADER_LEN:]
        if checkcontrol == True:
            if self.inetxcontrol != iNetX.CONTROLWORD:
                raise ValueError



    def randompayload(self,size):
        '''Generate a payload of 0x05'''
        self.payload = ''.join(['\x05' for num in xrange(size)])


    def parserpayload(self,parserblocks=1,quadbytes=1,count=0):
        '''Method will generate a parser aligned data payload. If you use this the performance of the data generation
        will decrease'''
        payload_list = []
        for i in range(parserblocks):
            parserblock = iNetXParser()
            parserblock.quadbytes = quadbytes
            parserblock.messagecount = count+i
            parserblock.randompayload()
            parserblock.buildpacket()
            payload_list.append(parserblock.packet)

        self.payload = "".join(payload_list)

    def _calcsize(self):
        udp_header_size = 50 # 8 + 14 + 20 + 8
        self.bytes = len(self.packet) + udp_header_size







