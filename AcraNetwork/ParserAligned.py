"""
.. module:: ParserAlignedPacket
    :platform: Unix, Windows
    :synopsis: Class to pack and unpack Parser Aligned payloads

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

import struct


__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


class ParserAlignedPacket(object):
    """
    A class that handles parser aligned packets. Unpack a buffer to populate the field into a list of parserblocks
    
    Capture a UDP packet,unpack as iNetX whose payload is parser aligned
    
    >>> import AcraNetwork.iNetX as inetx
    >>> import socket
    >>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = inetx.iNetX()
    >>> i.unpack(data)
    >>> p = ParserAlignedPacket()
    >>> p.unpack(i.payload)
    >>> print p
    
    :type parserblocks: list[ParserAlignedBlock]
    :type numberofblocks: int
    """

    def __init__(self):
        self.parserblocks = [] #: List of ParserAlignedBlock
        self.numberofblocks = 0 #: The number of ParserAlignedBlock

    def unpack(self, buf):
        """
        Pass a buffer containing all the Parser alignd payload and this method will
        unpack all the fields. Returns a list of parserblocks
    
        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """
        fullbufferlen = len(buf)
        bufferparsed = 0
        while bufferparsed < fullbufferlen:
            block = ParserAlignedBlock()
            # unpack and add the amount unpacked to the running total
            bufferparsed += block.unpack(buf[bufferparsed:])
            self.parserblocks.append(block)
        return True

    def pack(self):
        """Convert a ParserPacket to a buffer"""

        buf = bytes()
        for b in self.parserblocks:
            buf += b.pack()

        return buf

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.parserblocks):
            _block = self.parserblocks[self._index]
            self._index += 1
            return _block
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.parserblocks)

    def __getitem__(self, key):
        return self.parserblocks[key]

    def __repr__(self):
        rep = ""
        for idx, b in enumerate(self.parserblocks):
            rep += "Block {}: {}\n".format(idx, repr(b))
        return rep

    def __eq__(self, other):
        if not isinstance(other, ParserAlignedPacket):
            return False
        if len(other) != len(self):
            return False
        blk_cnt = len(other)
        for idx in range(blk_cnt):
            if other.parserblocks[idx] != self.parserblocks[idx]:
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

class ParserAlignedBlock(object):
    """
    A class to handle a single Parser Block. Returns an object containing all the fields of a parser block
    
    :type error: bool
    :type errorcode: int
    :type quadbytes: int
    :type messagecount: int
    :type busid: int
    :type elapsedtime: int
    :type payload: str
    """
    def __init__(self):

        self.error = False #: Error Flag
        self.errorcode = 0 #: Error code field
        self.quadbytes = 1 #: Number of quadbytes in the parser block
        self.messagecount = 0 #: Wrapping 8 bit message counter
        self.busid = 1 #: Bus ID on which the message was captured
        self.elapsedtime = 2 #: Time tag in nanoseconds offset from the iNetx timestamp
        self.payload = "" #: Payload

        self.format = '>HBBL'
        self.headerlen = struct.calcsize(self.format)

    def unpack(self, buf):
        """
        Unpack a single parser block. Unsually called only from the ParserAlignedPacket unpack method. 
        
        Returns the length of the parser block
        
        :param buf: The string buffer to unpack
        :type buf: str
        :rtype: int
        """

        # Unpack the fields
        (error_and_quad, self.messagecount, self.busid, self.elapsedtime)= struct.unpack_from(self.format, buf)
        # MSB bit is the error flag
        if (error_and_quad >> 15) == 1:
            self.error = True
        else:
            self.error = False

        # As error code and quad bytes are not byte aligned I have to do some shifting and masking
        self.errorcode = (error_and_quad >> 9) & 0x3f
        self.quadbytes = error_and_quad & 0x1ff
        payload_length_in_bytes = (self.quadbytes - 2)*4

        if self.quadbytes < 2:
            raise ValueError("The quad bytes cannot be less than 2. Actual={}".format(self.quadbytes))

        # Raise an exception if the payload is not as expected
        if len(buf) < self.headerlen + payload_length_in_bytes:
            raise ValueError("The length of the block buffer {} is smaller the expect length {}".format(
                len(buf), self.headerlen + payload_length_in_bytes
            ))

        self.payload = buf[self.headerlen:self.quadbytes*4]
        # Return the length of the block as a courtesy
        return self.quadbytes*4

    def pack(self):
        """
        Convert a ParserAlignedBlock into a buffer
        :return:
        """
        if len(self.payload) % 4 != 0:
            raise Exception("Length of payload is not aligned to quadbytes (32b)")
        self.quadbytes = 2 + len(self.payload) // 4
        error_and_quad = (self.error << 15) + ((self.errorcode & 0x3f) << 9) + self.quadbytes
        return struct.pack(self.format, error_and_quad, self.messagecount, self.busid, self.elapsedtime) + self.payload

    def __repr__(self):
        return "QuadBytes={} Error={} ErrorCode={} BusID={} MessageCount={} ElapsedTime={}".format(
            self.quadbytes, self.error, self.errorcode, self.busid, self.messagecount, self.elapsedtime
        )

    def __len__(self):
        return len(self.payload) + struct.calcsize(self.format)

    def __eq__(self, other):
        if not isinstance(other, ParserAlignedBlock):
            return False
        for attr in ["quadbytes", "error", "errorcode", "busid", "messagecount", "elapsedtime", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)


class ARINC429(object):
    """This is not working yet. Don't use it"""
    MESSAGE_LEN = 4 # 4 bytes
    LABEL_REVERSE = [
        0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, #   0 -   8
        0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0, #   9 -  15
        0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, #  16 -  23
        0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, #  24 -  31
        0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, #  32 -  39
        0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4, #  40 -  47
        0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, #  48 -  55
        0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc, #  56 -  63
        0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, #  64 -  71
        0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2, #  72 -  79
        0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, #  80 -  87
        0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa, #  88 -  95
        0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, #  96 - 103
        0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6, # 104 - 111
        0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, # 112 - 119
        0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe, # 120 - 127
        0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, # 128 - 135
        0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1, # 136 - 143
        0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, # 144 - 151
        0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9, # 152 - 159
        0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, # 160 - 167
        0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5, # 168 - 175
        0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, # 176 - 183
        0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd, # 184 - 191
        0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, # 192 - 199
        0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3, # 200 - 207
        0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, # 208 - 215
        0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, # 216 - 223
        0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, # 224 - 231
        0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7, # 232 - 239
        0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, # 240 - 247
        0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff, # 248 - 255
        0x00
    ]

    def __init__(self):
        self.parity = None
        self.ssm = None
        self.data = None
        self.sdi = None
        self.label = None

    def unpack(self,buf):
        if len(buf) != ARINC429.MESSAGE_LEN:
            raise ValueError("Buffer is not the correct length for an ARINC429 message")
        (byte1,byte2,byte3,byte4) = struct.unpack('BBBB',buf)
        self.parity = byte1 / 128
        self.ssm = (byte1/32) % 4
        self.data = ((byte1 %32) * 256 + byte2 ) * 64 + (byte3 /4)
        self.sdi = byte3 % 4
        self.label = ARINC429.LABEL_REVERSE[byte4]



