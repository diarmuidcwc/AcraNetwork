import struct


class UARTDataPacket(object):
    """
    Data Packet Format. Contains a list of UART Data Words

    :type msgcount: int
    :type uartwords: list[UARTDataWord]


    >>> c = Chapter10UDP()
    >>> uart_p = UARTDataPacket()
    >>> uart_p.unpack(c.chapter10.payload))
    >>> print uart_p


    """

    def __init__(self):
        self.uartwords = []  #: List of :class:`UARTDataWord`

    def pack(self):
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str
        """
        # Some checks
        if len(self) == 0:
            raise Exception("No UARTDataWords defined")

        # All words should have the same configuraiton of timestamps
        ts_present = None
        for udw in self:
            if ts_present is None:
                ts_present = (udw.ptptimeseconds is not None)
            elif ts_present != (udw.ptptimeseconds is not None):
                raise Exception("All UARTDataWords should either have or have not a PTPTimestamp header")
        if ts_present is not None:
            ret_buf = struct.pack("<I", int(ts_present) << 31)
        else:
            raise Exception("Timestamp is none")
        for udw in self:
            ret_buf += udw.pack()

        return ret_buf

    def unpack(self, mybuffer):
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
            udw = UARTDataWord()
            offset += udw.unpack(mybuffer[offset:], ts_present)
            self.uartwords.append(udw)

        return True

    def append(self, udw):
        """
        Add a UART DW to the DP

        :type udw: UARTDataWord
        :rtype: bool
        """
        if not isinstance(udw, UARTDataWord):
            raise Exception("Can only append UARTDataWords")
        return self.uartwords.append(udw)

    def __eq__(self, other):
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

    def next(self):
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

    def __init__(self):
        self.ptptimeseconds = None #: Timestamp of first parameter in the packet. EPOCH time
        self.ptptimenanoseconds = None #: Nanaosecond timestamp
        self.parity_error = False  #: Parity error has occurred
        self.subchannel = 0  #: Subchannel
        self.datalength = None  #: Data Length
        self._payload = b""  #: UART payload

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, mybuffer):

        self._payload = mybuffer
        self.datalength = len(mybuffer)

    def pack(self):
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str|bytes
        """
        if self.ptptimeseconds is not None and self.ptptimenanoseconds is not None:
            ch_spec_word = struct.pack("<II",self.ptptimenanoseconds, self.ptptimeseconds)
        else:
            ch_spec_word = b""
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

        return ch_spec_word + intra_pkt_header + self.payload + padding

    def unpack(self, mybuffer, timestamp_present=True):
        """
        Unpack a string buffer into an UART data packet object. Returns the buffer that was consumed

        :param mybuffer: A string buffer representing an UART data  packet
        :type mybuffer: str
        :param timestamp_present: The UART DataPacket Format knows if there is a timestamp or not
        :type timestamp_present: bool
        :rtype: int
        """
        offset = 0
        if timestamp_present:
            #bytes = struct.unpack_from(">8B", mybuffer)
            (self.ptptimenanoseconds, self.ptptimeseconds) = struct.unpack_from("<II", mybuffer, offset)
            offset += 8
        (self.datalength, _pe_sub) = struct.unpack_from("<HH", mybuffer, offset)
        offset += 4

        self.subchannel = _pe_sub & 0x1FFF
        self.parity_error = bool(_pe_sub >> 15)
        self.payload = mybuffer[offset:offset+self.datalength]
        offset += self.datalength

        if self.datalength % 2 == 1:
            return offset + 1
        else:
            return offset

    def __eq__(self, other):
        if not isinstance(other, UARTDataWord):
            return False

        _match_att = ["ptptimeseconds", "ptptimenanoseconds", "parity_error", "subchannel", "datalength", "payload"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "UARTDataWord: PTPSec={} PTPNSec={} ParityError={} DataLen={} SubChannel={}".format(
             self.ptptimeseconds, self.ptptimenanoseconds, self.parity_error, self.datalength, self.subchannel)
