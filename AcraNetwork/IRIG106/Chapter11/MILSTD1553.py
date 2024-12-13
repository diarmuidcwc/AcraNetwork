from __future__ import annotations
import struct
from AcraNetwork.IRIG106.Chapter11 import TS_CH4, TS_IEEE1558, RTCTime, PTPTime
import typing


class MILSTD1553Message(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles MIL1553 packets

    :type ptptimeseconds: int
    :type ptptimenanoseconds: int
    :type subchannel: int
    :type parity_error: bool
    :type datalength: int
    :type payload: str
    """

    def __init__(self, ipts_source: int = TS_CH4):
        if ipts_source == TS_CH4:
            self.ipts = RTCTime()
        elif ipts_source == TS_IEEE1558:
            self.ipts = PTPTime()
        elif ipts_source is None:
            raise Exception("Time stamp is not option for MIL-STD-1553")
        self.blockstatus: int = 0
        self.gaptimes: int = 0
        self.length: int = 0
        self.message: bytes = bytes()

    def pack(self):
        """
        Pack the MIL-STD-1553 message object into a binary buffer

        :rtype: bytes
        """
        ch_spec_word = self.ipts.pack()
        self.length = len(self.message)
        intra_packet_data_header = struct.pack("<HHH", self.blockstatus, self.gaptimes, self.length)

        return ch_spec_word + intra_packet_data_header + self.message

    def unpack(self, mybuffer: bytes):
        """
        Unpack a string buffer into an MIL-STD-1553 data packet object. Returns the buffer that was consumed

        :param mybuffer: A string buffer representing an UART data  packet
        :type mybuffer: str
        :rtype: int
        """
        offset = 0
        # bytes = struct.unpack_from(">8B", mybuffer)
        self.ipts.unpack(mybuffer[:8])
        offset += 8
        (self.blockstatus, self.gaptimes, self.length) = struct.unpack_from("<HHH", mybuffer, offset)
        offset += 6
        self.message = mybuffer[offset : offset + self.length]
        offset += self.length

        return offset

    def __eq__(self, other: MILSTD1553Message):
        if not isinstance(other, MILSTD1553Message):
            return False

        _match_att = ["ipts", "blockstatus", "gaptimes", "length", "message"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "MILSTD1553Message: Time={}  BlockStatus={} GapTimes={} Length={}".format(
            self.ipts, self.blockstatus, self.gaptimes, self.length
        )


class MILSTD1553DataPacket(object):
    """
    Data Packet Format. Contains a list of MIML-STD-1553 Data Words

    :type msgcount: int
    :type uartwords: list[MILSTD1553Message]


    >>> from AcraNetwork.IRIG106.Chapter11 import Chapter11
    >>> c = Chapter11()
    >>> m = MILSTD1553DataPacket()
    >>> milmessage = MILSTD1553Message()
    >>> milmessage.message = bytes(2)
    >>> m.append(milmessage)
    >>> c.payload = m.pack()
    >>> ch10_buffer = c.pack()
    >>> # Now reverse the process
    >>> c2 = Chapter11()
    >>> c2.unpack(ch10_buffer)
    True
    >>> m2 =  MILSTD1553DataPacket()
    >>> m2.unpack(c2.payload)
    True
    >>> print(m2)
    MILSTD1553DataPacket: MessageCount=1 [MILSTD1553Message: Time=RTC: count=0  BlockStatus=0 GapTimes=0 Length=2]
      MILSTD1553Message: Time=RTC: count=0  BlockStatus=0 GapTimes=0 Length=2
    <BLANKLINE>
    >>> print(m2.msgcount)
    1

    """

    def __init__(self, ipts_source=TS_CH4):
        self.messages: typing.List[MILSTD1553Message] = []  #: List of :class:`MILSTD1553Message`
        self.msgcount: int = 0
        self.ttb: int = 0
        self._ipts_source = ipts_source

    def pack(self):
        """
        Pack the MIL-STD-1553 data packet object into a binary buffer

        :rtype: str
        """
        # Some checks
        if len(self) == 0:
            raise Exception("No MILSTD1553Messages defined")

        msg_buf = bytes()
        for dw in self:
            msg_buf += dw.pack()

        csw = struct.pack("<I", (self.ttb << 30) + len(self))

        return csw + msg_buf

    def unpack(self, mybuffer):
        """
        Unpack a string buffer into an UART data packet object

        :param buffer: A string buffer representing an UART data  packet
        :type buffer: str
        :rtype: None
        """

        (ch_spec_word,) = struct.unpack_from("<I", mybuffer)
        self.msgcount = ch_spec_word & 0xFFFFFF
        self.ttb = (ch_spec_word >> 30) & 0x3

        offset = 4
        while offset + 14 < len(mybuffer):  # Should have at least the timestamp
            m = MILSTD1553Message(self._ipts_source)
            offset += m.unpack(mybuffer[offset:])
            self.messages.append(m)

        return True

    def append(self, message: MILSTD1553Message):
        """
        Add a message to the data packet

        :type message: MILSTD1553Message
        :rtype: bool
        """
        if not isinstance(message, MILSTD1553Message):
            raise Exception("Can only append MILSTD1553Message")
        self.msgcount += 1
        return self.messages.append(message)

    def __eq__(self, other):
        if not isinstance(other, MILSTD1553DataPacket):
            return False

        _match_att = ["messages", "msgcount"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str = "MILSTD1553DataPacket: MessageCount={} {}\n".format(self.msgcount, self.messages)

        for a in self:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self) -> MILSTD1553Message:
        if self._index < len(self.messages):
            _dw = self.messages[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.messages)

    def __getitem__(self, key):
        return self.messages[key]
