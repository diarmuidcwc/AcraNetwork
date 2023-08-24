"""
.. module:: ParserAlignedPacket
    :platform: Unix, Windows
    :synopsis: Class to pack and unpack Parser Aligned payloads

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

import struct
import typing

__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


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
        self.error: bool = False  #: Error Flag
        self.errorcode: int = 0  #: Error code field
        self.quadbytes: int = 1  #: Number of quadbytes in the parser block
        self.messagecount: int = 0  #: Wrapping 8 bit message counter
        self.busid: int = 1  #: Bus ID on which the message was captured
        self.elapsedtime: int = 2  #: Time tag in nanoseconds offset from the iNetx timestamp
        self.payload: bytes = bytes()  #: Payload

        self.format = ">HBBL"
        self.headerlen = struct.calcsize(self.format)

    def unpack(self, buf: bytes):
        """
        Unpack a single parser block. Unsually called only from the ParserAlignedPacket unpack method.

        Returns the length of the parser block

        :param buf: The string buffer to unpack
        :type buf: str
        :rtype: int
        """

        # Unpack the fields
        (error_and_quad, self.messagecount, self.busid, self.elapsedtime) = struct.unpack_from(self.format, buf)
        # MSB bit is the error flag
        if (error_and_quad >> 15) == 1:
            self.error = True
        else:
            self.error = False

        # As error code and quad bytes are not byte aligned I have to do some shifting and masking
        self.errorcode = (error_and_quad >> 9) & 0x3F
        self.quadbytes = error_and_quad & 0x1FF
        payload_length_in_bytes = (self.quadbytes - 2) * 4

        if self.quadbytes < 2:
            raise ValueError("The quad bytes cannot be less than 2. Actual={}".format(self.quadbytes))

        # Raise an exception if the payload is not as expected
        if len(buf) < self.headerlen + payload_length_in_bytes:
            raise ValueError(
                "The length of the block buffer {} is smaller the expect length {}".format(
                    len(buf), self.headerlen + payload_length_in_bytes
                )
            )

        self.payload = buf[self.headerlen : self.quadbytes * 4]
        # Return the length of the block as a courtesy
        return self.quadbytes * 4

    def pack(self) -> bytes:
        """
        Convert a ParserAlignedBlock into a buffer
        :return:
        """
        if len(self.payload) % 4 != 0:
            raise Exception("Length of payload is not aligned to quadbytes (32b)")
        self.quadbytes = 2 + len(self.payload) // 4
        error_and_quad = (self.error << 15) + ((self.errorcode & 0x3F) << 9) + self.quadbytes
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
        self.parserblocks: typing.List[ParserAlignedBlock] = []  #: List of ParserAlignedBlock
        self.numberofblocks: int = 0  #: The number of ParserAlignedBlock

    def unpack(self, buf: bytes):
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


class ARINC429(object):
    """This is not working yet. Don't use it"""

    MESSAGE_LEN = 4  # 4 bytes
    LABEL_REVERSE = [
        0x00,
        0x80,
        0x40,
        0xC0,
        0x20,
        0xA0,
        0x60,
        0xE0,  # 0 -   8
        0x10,
        0x90,
        0x50,
        0xD0,
        0x30,
        0xB0,
        0x70,
        0xF0,  # 9 -  15
        0x08,
        0x88,
        0x48,
        0xC8,
        0x28,
        0xA8,
        0x68,
        0xE8,  # 16 -  23
        0x18,
        0x98,
        0x58,
        0xD8,
        0x38,
        0xB8,
        0x78,
        0xF8,  # 24 -  31
        0x04,
        0x84,
        0x44,
        0xC4,
        0x24,
        0xA4,
        0x64,
        0xE4,  # 32 -  39
        0x14,
        0x94,
        0x54,
        0xD4,
        0x34,
        0xB4,
        0x74,
        0xF4,  # 40 -  47
        0x0C,
        0x8C,
        0x4C,
        0xCC,
        0x2C,
        0xAC,
        0x6C,
        0xEC,  # 48 -  55
        0x1C,
        0x9C,
        0x5C,
        0xDC,
        0x3C,
        0xBC,
        0x7C,
        0xFC,  # 56 -  63
        0x02,
        0x82,
        0x42,
        0xC2,
        0x22,
        0xA2,
        0x62,
        0xE2,  # 64 -  71
        0x12,
        0x92,
        0x52,
        0xD2,
        0x32,
        0xB2,
        0x72,
        0xF2,  # 72 -  79
        0x0A,
        0x8A,
        0x4A,
        0xCA,
        0x2A,
        0xAA,
        0x6A,
        0xEA,  # 80 -  87
        0x1A,
        0x9A,
        0x5A,
        0xDA,
        0x3A,
        0xBA,
        0x7A,
        0xFA,  # 88 -  95
        0x06,
        0x86,
        0x46,
        0xC6,
        0x26,
        0xA6,
        0x66,
        0xE6,  # 96 - 103
        0x16,
        0x96,
        0x56,
        0xD6,
        0x36,
        0xB6,
        0x76,
        0xF6,  # 104 - 111
        0x0E,
        0x8E,
        0x4E,
        0xCE,
        0x2E,
        0xAE,
        0x6E,
        0xEE,  # 112 - 119
        0x1E,
        0x9E,
        0x5E,
        0xDE,
        0x3E,
        0xBE,
        0x7E,
        0xFE,  # 120 - 127
        0x01,
        0x81,
        0x41,
        0xC1,
        0x21,
        0xA1,
        0x61,
        0xE1,  # 128 - 135
        0x11,
        0x91,
        0x51,
        0xD1,
        0x31,
        0xB1,
        0x71,
        0xF1,  # 136 - 143
        0x09,
        0x89,
        0x49,
        0xC9,
        0x29,
        0xA9,
        0x69,
        0xE9,  # 144 - 151
        0x19,
        0x99,
        0x59,
        0xD9,
        0x39,
        0xB9,
        0x79,
        0xF9,  # 152 - 159
        0x05,
        0x85,
        0x45,
        0xC5,
        0x25,
        0xA5,
        0x65,
        0xE5,  # 160 - 167
        0x15,
        0x95,
        0x55,
        0xD5,
        0x35,
        0xB5,
        0x75,
        0xF5,  # 168 - 175
        0x0D,
        0x8D,
        0x4D,
        0xCD,
        0x2D,
        0xAD,
        0x6D,
        0xED,  # 176 - 183
        0x1D,
        0x9D,
        0x5D,
        0xDD,
        0x3D,
        0xBD,
        0x7D,
        0xFD,  # 184 - 191
        0x03,
        0x83,
        0x43,
        0xC3,
        0x23,
        0xA3,
        0x63,
        0xE3,  # 192 - 199
        0x13,
        0x93,
        0x53,
        0xD3,
        0x33,
        0xB3,
        0x73,
        0xF3,  # 200 - 207
        0x0B,
        0x8B,
        0x4B,
        0xCB,
        0x2B,
        0xAB,
        0x6B,
        0xEB,  # 208 - 215
        0x1B,
        0x9B,
        0x5B,
        0xDB,
        0x3B,
        0xBB,
        0x7B,
        0xFB,  # 216 - 223
        0x07,
        0x87,
        0x47,
        0xC7,
        0x27,
        0xA7,
        0x67,
        0xE7,  # 224 - 231
        0x17,
        0x97,
        0x57,
        0xD7,
        0x37,
        0xB7,
        0x77,
        0xF7,  # 232 - 239
        0x0F,
        0x8F,
        0x4F,
        0xCF,
        0x2F,
        0xAF,
        0x6F,
        0xEF,  # 240 - 247
        0x1F,
        0x9F,
        0x5F,
        0xDF,
        0x3F,
        0xBF,
        0x7F,
        0xFF,  # 248 - 255
        0x00,
    ]

    def __init__(self):
        self.parity = None
        self.ssm = None
        self.data = None
        self.sdi = None
        self.label = None

    def unpack(self, buf):
        if len(buf) != ARINC429.MESSAGE_LEN:
            raise ValueError("Buffer is not the correct length for an ARINC429 message")
        (byte1, byte2, byte3, byte4) = struct.unpack("BBBB", buf)
        self.parity = byte1 / 128
        self.ssm = (byte1 / 32) % 4
        self.data = ((byte1 % 32) * 256 + byte2) * 64 + (byte3 / 4)
        self.sdi = byte3 % 4
        self.label = ARINC429.LABEL_REVERSE[byte4]
