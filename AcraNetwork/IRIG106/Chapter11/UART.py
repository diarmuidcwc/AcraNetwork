import struct
from AcraNetwork.IRIG106.Chapter11 import TS_CH4, TS_IEEE1558, RTCTime, PTPTime
from enum import IntEnum, unique
import typing


@unique
class Endianness(IntEnum):
    BIG: int = 0
    LITTLE: int = 1


def endian_swap(buffer: bytes) -> bytes:
    return bytearray([c for t in zip(buffer[1::2], buffer[::2]) for c in t])


class UARTDataWord(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles UART packets

    :type ptptimeseconds: int
    :type ptptimenanoseconds: int
    :type subchannel: int
    :type parity_error: bool
    :type datalength: int
    :type payload: str
    """

    def __init__(self, ipts_source=TS_CH4, data_endianness: int = Endianness.BIG):
        if ipts_source == TS_CH4:
            self.ipts = RTCTime()
        elif ipts_source == TS_IEEE1558:
            self.ipts = PTPTime()
        elif ipts_source is None:
            self.ipts = None
        self.parity_error: bool = False  #: Parity error has occurred
        self.subchannel: int = 0  #: Subchannel
        self.datalength: int = None  #: Data Length
        self._payload: bytes = bytes()  #: UART payload
        self.data_endianness: int = data_endianness

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, mybuffer: bytes):
        self._payload = mybuffer
        self.datalength = len(mybuffer)

    def pack(self) -> bytes:
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str|bytes
        """
        if self.ipts is None:
            ch_spec_word = b""
        else:
            ch_spec_word = self.ipts.pack()
        data_len = len(self.payload)
        if self.parity_error:
            _subch = self.subchannel + 0x80
        else:
            _subch = self.subchannel
        intra_pkt_header = struct.pack("<HH", data_len, _subch)

        if data_len % 2 == 1:
            padding = struct.pack("B", 0xFF)
        else:
            padding = b""

        payload_and_padding = self.payload + padding
        if self.data_endianness == Endianness.LITTLE:
            payload_and_padding = endian_swap(payload_and_padding)
        return ch_spec_word + intra_pkt_header + payload_and_padding

    def unpack(self, mybuffer: bytes):
        """
        Unpack a string buffer into an UART data packet object. Returns the buffer that was consumed

        :param mybuffer: A string buffer representing an UART data  packet
        :type mybuffer: str
        :param timestamp_present: The UART DataPacket Format knows if there is a timestamp or not
        :type timestamp_present: bool
        :rtype: int
        """
        offset = 0
        if self.ipts is not None:
            # bytes = struct.unpack_from(">8B", mybuffer)
            self.ipts.unpack(mybuffer[:8])
            offset += 8
        (self.datalength, _pe_sub) = struct.unpack_from("<HH", mybuffer, offset)
        offset += 4

        self.subchannel = _pe_sub & 0x1FFF
        self.parity_error = bool(_pe_sub >> 15)

        if self.data_endianness == Endianness.LITTLE:
            if self.datalength % 2 == 1:
                payload_and_padding = mybuffer[offset : offset + self.datalength + 1]  # take the buffer and the payload
                payload_and_padding = endian_swap(payload_and_padding)
                payload_and_padding = payload_and_padding[:-1]
            else:
                payload_and_padding = mybuffer[offset : offset + self.datalength]
                payload_and_padding = endian_swap(payload_and_padding)
        else:
            payload_and_padding = mybuffer[offset : offset + self.datalength]

        self.payload = payload_and_padding
        offset += self.datalength

        if self.datalength % 2 == 1:
            return offset + 1
        else:
            return offset

    def __eq__(self, other):
        if not isinstance(other, UARTDataWord):
            return False

        _match_att = ["ipts", "parity_error", "subchannel", "datalength", "payload"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return f"UARTDataWord: Time={self.ipts} ParityError={self.parity_error} DataLen={self.datalength} SubChannel={self.subchannel} Endianness={repr(self.data_endianness)}"


class UARTDataPacket(object):
    """
    Data Packet Format. Contains a list of UART Data Words

    :type msgcount: int
    :type uartwords: list[UARTDataWord]


    >>> import AcraNetwork.Pcap as pcap
    >>> from AcraNetwork.IRIG106.Chapter11 import Chapter11
    >>> p = pcap.Pcap("test/sample_pcap/sample_ch10uart.pcap")
    >>> data = p[0].payload
    >>> c = Chapter11()
    >>> c.unpack(data[0x2E:])
    True
    >>> uart_p = UARTDataPacket()
    >>> uart_p.unpack(c.payload)
    True
    >>> print(len(uart_p))
    22
    >>> print(uart_p[0])
    UARTDataWord: Time=RTC: count=43151323112 ParityError=True DataLen=34 SubChannel=0 Endianness=<Endianness.BIG: 0>

    """

    def __init__(self, ipts_source=TS_CH4, data_endianness: int = Endianness.BIG):
        self.uartwords: typing.List[UARTDataWord] = []  #: List of :class:`UARTDataWord`
        self._ipts_source = ipts_source
        self.data_endianness: int = data_endianness

    def pack(self) -> bytes:
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str
        """
        # Some checks
        if len(self) == 0:
            raise Exception("No UARTDataWords defined")

        # All words should have the same configuraiton of timestamps
        if self._ipts_source is not None:
            ret_buf = struct.pack("<I", 0x1 << 31)
        else:
            ret_buf = struct.pack("<I", 0x0 << 31)

        for udw in self:
            ret_buf += udw.pack()

        return ret_buf

    def unpack(self, mybuffer: bytes):
        """
        Unpack a string buffer into an UART data packet object

        :param buffer: A string buffer representing an UART data  packet
        :type buffer: str
        :rtype: None
        """

        (ch_spec_word,) = struct.unpack_from("<I", mybuffer)
        ts_present = bool(ch_spec_word >> 31)
        offset = 4
        while abs(offset - len(mybuffer)) > 4:
            udw = UARTDataWord(self._ipts_source, self.data_endianness)
            offset += udw.unpack(mybuffer[offset:])
            self.uartwords.append(udw)

        return True

    def append(self, udw: UARTDataWord):
        """
        Add a UART DW to the DP

        :type udw: UARTDataWord
        :rtype: bool
        """
        if not isinstance(udw, UARTDataWord):
            raise Exception("Can only append UARTDataWords")
        return self.uartwords.append(udw)

    def __eq__(self, other: UARTDataWord):
        if not isinstance(other, UARTDataPacket):
            return False

        _match_att = ["uartwords"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str = "UARTPayload: UARTDataWordCount={}\n".format(len(self))

        for a in self:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self) -> UARTDataWord:
        if self._index < len(self.uartwords):
            _dw = self.uartwords[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.uartwords)

    def __getitem__(self, key):
        return self.uartwords[key]
