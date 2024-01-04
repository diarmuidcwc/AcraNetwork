import struct


class ARINC429DataWord(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles AROINC-429 packets

    :type msgcount: int
    :type gaptime: int
    :type format_error: bool
    :type parity_error: bool
    :type bus_speed: int
    :type bus: int
    :type payload: str
    """

    LO_SPEED = 0  #: Bus speed constant
    HI_SPEED = 1  #: Bus speed constant

    HDR_FORMAT = ">HBB"

    def __init__(self):
        self.gaptime = 0  #: The gap time from the beginning of the preceding bus word (regardless of bus) to the
        # beginning of the current bus word in 0.1-us increments
        self.format_error = False  #: Format error has occurred
        self.parity_error = False  #: Parity error has occurred
        self.bus_speed = ARINC429DataWord.LO_SPEED  #: Arinc bus speed
        self.bus = None  #: Bus number index from 0
        self.payload = b""  #: ARINC word as a string payload

    def pack(self):
        """
        Pack the ARINC-429 data packet object into a binary buffer

        :rtype: str|bytes
        """
        _flag = (self.format_error << 7) + (self.parity_error << 6) + (self.bus_speed << 5) + (self.gaptime >> 16)
        _gap = self.gaptime & 0xFFFF
        hdr = struct.pack(ARINC429DataWord.HDR_FORMAT, _gap, _flag, self.bus)

        return hdr + self.payload

    def unpack(self, buffer):
        """
        Unpack a string buffer into an ARINC-429 data packet object

        :param buffer: A string buffer representing an ARINC-429 data  packet
        :type buffer: str
        :rtype: None
        """
        (_gap, _flag, self.bus) = struct.unpack_from(ARINC429DataWord.HDR_FORMAT, buffer)
        self.payload = buffer[struct.calcsize(ARINC429DataWord.HDR_FORMAT) :]
        self.format_error = bool((_flag >> 7) & 0x1)
        self.parity_error = bool((_flag >> 6) & 0x1)
        self.bus_speed = (_flag >> 6) & 0x1
        self.gaptime = (_flag << 16) + _gap

        return True

    def __eq__(self, other):
        if not isinstance(other, ARINC429DataWord):
            return False

        _match_att = ("gaptime", "format_error", "parity_error", "bus_speed", "bus", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "ARINCData: GapTime={} FormatError={} ParityError={} BusSpeed={} Bus={}".format(
            self.gaptime, self.format_error, self.parity_error, self.bus_speed, self.bus
        )


class ARINC429DataPacket(object):
    """
    Data Packet Format. Contains a list of Arinc Data Words

    :type msgcount: int
    :type arincwords: list[ARINC429DataWord]


    >>> c = Chapter10UDP()
    >>> arinc_p = ARINC429DataPacket()
    >>> arinc_p.unpack(c.chapter10.payload))
    >>> print arinc_p
    ARINCPayload: MessageCount=0
      ARINCData: GapTime=0 FormatError=False ParityError=False BusSpeed=0 Bus=0

    """

    def __init__(self):
        self.msgcount = None  #: The number ofARINC-429 words included in the packet.
        self.arincwords = []  #: List of :class:`ARINC429DataWord`

    def pack(self):
        """
        Pack the ARINC-429 data packet object into a binary buffer

        :rtype: str
        """
        ret_str = struct.pack("<HH", self.msgcount, 0)
        for a in self.arincwords:
            ret_str += a.pack()

        return ret_str

    def unpack(self, buffer):
        """
        Unpack a string buffer into an ARINC-429 data packet object

        :param buffer: A string buffer representing an ARINC-429 data  packet
        :type buffer: str
        :rtype: None
        """
        CH_SPECIFIC_HDR_LEN = 4
        ARINC_WORD_LEN = 8
        (self.msgcount, _res) = struct.unpack_from("<HH", buffer)
        exp_msg = (len(buffer) - CH_SPECIFIC_HDR_LEN) // ARINC_WORD_LEN
        for msg_idx in range(exp_msg):
            offset = (msg_idx * ARINC_WORD_LEN) + CH_SPECIFIC_HDR_LEN
            arinc_data = ARINC429DataWord()
            arinc_msg_word_buffer = buffer[offset : offset + ARINC_WORD_LEN]
            arinc_data.unpack(arinc_msg_word_buffer)
            self.arincwords.append(arinc_data)

        if self.msgcount != len(self.arincwords):
            raise Exception(
                "The ARINC Message Count={} does not match number of messages in the packet={}".format(
                    self.msgcount, len(self.arincwords)
                )
            )
        return True

    def __eq__(self, other):
        if not isinstance(other, ARINC429DataPacket):
            return False

        _match_att = ("msgcount", "arincwords")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str = "ARINCPayload: MessageCount={}\n".format(self.msgcount)

        for a in self.arincwords:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self) -> ARINC429DataWord:
        if self._index < len(self.arincwords):
            _dw = self.arincwords[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.arincwords)

    def __getitem__(self, key):
        return self.arincwords[key]
