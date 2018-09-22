"""
.. module:: Chapter10
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct Chapter10 Packets

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct


def get_checksum_buf(buf):
    """
    Return the arithmetic checksum of a header

    :param buf:
    :return:
    """
    if len(buf) % 2 != 0:
        raise Exception("buffer needsto be 16-bit aligned")

    words = struct.unpack("<{}H".format(len(buf)/2), buf)
    sum = reduce(lambda x, y: x + y, words)

    return sum % 65536


class Chapter10UDP(object):
    """ 
    Class to encapsulate Chapter10 payload in UDP packets

    Capture a UDP packet and unpack the payload as an Chapter 10 packet
    
    There are two types of packets, segmented and full. 

    >>> import socket
    >>>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> n = Chapter10UDP()
    >>> n.unpack(data)
    >>> print n.type
    0

    :type version: int
    :type type: int
    :type hdrlen: int
    :type channelID: int
    :type channelsequence: int
    :type segmentoffset: int
    :type chapter10: Chapter10
    """

    CH10_UDP_HEADER_FORMAT = '<BBH'
    CH10_UDP_SEG_HEADER_FORMAT = '<HBBI'
    CH10_UDP_HEADER_LENGTH = struct.calcsize(CH10_UDP_HEADER_FORMAT)
    CH10_UDP_SEG_HEADER_LENGTH = struct.calcsize(CH10_UDP_SEG_HEADER_FORMAT)

    TYPE_FULL = 0  #: Full Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`
    TYPE_SEG = 1  #: Segmented Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`

    def __init__(self):
        '''Creator method for a UDP class'''
        self.version = 1  #: Version
        self.type = None  #: Type of message , Full or Segmented
        self.channelID = None  #: Segmented Packets Only. Channel ID of the data in the RCC 106 Chapter 10 packet
        self.channelsequence = None  #: Segmented Packets Only, Channel Sequence Number of the data in the RCC 106 Chapter 10 packet
        self.sequence = None  #: Segmented Packets Only. Binary value incrementing by one for each UDP message even if segment of RCC 106 Chapter 10 packet.
        self.segmentoffset = None  #: Segmented Packets Only. The 32-bit Segmented Packets Only, Position of the data in the RCC 106 Chapter 10 packet.
        self.chapter10 = Chapter10() #: The encapsulated Chapter10 packet. :class:`Chapter10`

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10UDP object

        :param buffer: A string buffer representing an Chapter10UDP packet
        :type buffer: str
        :rtype: None
        """
        (_ver_type, seg_lwr, seg_upr) = struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT, buffer)
        self.version = _ver_type & 0xF
        self.type = _ver_type >> 4
        self.sequence = seg_lwr + (seg_upr << 8)

        if self.type == Chapter10UDP.TYPE_SEG:
            (self.channelID, self.channelsequence, _res, self.segmentoffset) = \
                struct.unpack_from(Chapter10UDP.CH10_UDP_SEG_HEADER_FORMAT, buffer, Chapter10UDP.CH10_UDP_HEADER_LENGTH)
            _payload = buffer[(Chapter10UDP.CH10_UDP_HEADER_LENGTH + Chapter10UDP.CH10_UDP_SEG_HEADER_LENGTH):]
        else:
            _payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH:]

        return self.chapter10.unpack(_payload)

    def pack(self):
        """
        Pack the Chapter10UDP object into a binary buffer

        :rtype: str 
        """

        _ver_type = (self.type << 4) + self.version
        seg_up = self.sequence >> 8
        seg_lr = self.sequence & 0xFF

        _packet = struct.pack(Chapter10UDP.CH10_UDP_HEADER_FORMAT, _ver_type, seg_lr, seg_up)

        if self.type == Chapter10UDP.TYPE_SEG:
            _packet += struct.pack(Chapter10UDP.CH10_UDP_SEG_HEADER_FORMAT, self.channelID, self.channelsequence, 0, self.segmentoffset)
            _packet += self.chapter10.pack()
        else:
            _packet += self.chapter10.pack()

        return _packet

    def __repr__(self):
        if self.type == Chapter10UDP.TYPE_FULL:
            return "CH10 UDP Full Packet: Version={} Sequence={} Payload={}".format(
                self.version, self.sequence, repr(self.chapter10))
        else:
            return "CH10 UDP Sequence: Version={} Sequence={} ChID={} ChSeqNum={} SegOffset={}".format(
                self.version, self.sequence, self.channelID, self.channelsequence, self.segmentoffset)

    def __eq__(self, other):
        if not isinstance(other, Chapter10UDP):
            return False

        if other.version == Chapter10UDP.TYPE_SEG:
            _match_att = ("version", "type", "sequence", "channelID", "channelsequence", "segmentoffset")
        else:
            _match_att = ("version", "type", "sequence")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True


class Chapter10(object):
    """
    Class to pack and unpack Chapter10 payloads. 
    
    Create a packet and transmit it via UDP
    
    >>> import socket
    >>> # Open a socket
    >>> tx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> # Create the Ch10 UDP wrapper
    >>> ch10_udp = Chapter10UDP()
    >>> ch10_udp.type = Chapter10UDP.TYPE_FULL
    >>> # Populate the Chapter 10 packet inthe wrapper
    >>> ch10_udp.chapter10.channelID = 1
    >>> ch10_udp.chapter10.datatypeversion = 2
    >>> ch10_udp.chapter10.sequence = 3
    >>> ch10_udp.chapter10.packetflag = 0 # No secondary
    >>> ch10_udp.chapter10.datatype = 4
    >>> ch10_udp.chapter10.relativetimecounter = 100
    >>> ch10_udp.chapter10.payload = struct.pack(">II", 33, 44)
    >>> # Send the packet
    >>> tx_socket.sendto(ch10_udp.pack(), ("127.0.0.1", 8010))
    True

    :type syncpattern: int
    :type channelID: int
    :type packetlen: int
    :type datalen: int
    :type datatypeversion: int
    :type sequence: int
    :type datatype: int
    :type relativetimecounter: int
    :type timestamp: int
    :type ts_source: str
    :type payload: str
    :type data_checksum_size: int
    :type filler: str
    """

    SYNC_WORD = 0xEB25  #:(Object Constant) Sync word

    CH10_HDR_FORMAT = "<HHIIBBBBIHH"
    CH10_HDR_FORMAT_LEN = struct.calcsize(CH10_HDR_FORMAT)

    CH10_OPT_HDR_FORMAT = "<IIHH"
    CH10_OPT_HDR_FORMAT_LEN = struct.calcsize(CH10_OPT_HDR_FORMAT)

    TS_SOURCES = ["rtc", "ch4", "ieee1588"] #:(Object Constant) Valid timesources, assign to :attr:`Chapter10.ts_source`

    PKT_FLAG_SECONDARY = 0x80  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_SEC_HDR_TIME = 0x40  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RTC_SYNC_ERROR = 0x20  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_DATA_OVERFLOW = 0X10  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RCC_TIME = 0X0  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_1588_TIME = 0X04  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_8BIT_CHKSUM = 0X1  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_16BIT_CHKSUM = 0X2  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_32BIT_CHKSUM = 0X3  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable

    def __init__(self):

        self.syncpattern = Chapter10.SYNC_WORD  #:(2 Bytes) contains a static sync value for the every packet. The Packet Sync Pattern value shall be 0xEB25
        self.channelID = None  #:(2 Bytes) contains a value representing the Packet Channel ID.
        self.packetlen = None  #:(4 Bytes) contains a value representing the length of the entire packet. The value shall be in bytes and is always a multiple of four
        self.datalen = None  #:(4 Bytes) contains a value representing the valid data length within the packet
        self.datatypeversion = 0x5  #: RCC released versions
        self.sequence= None  #:(1 Byte) contains a value representing the packet sequence number for each Channel ID.
        self._packetflag = None  #:(1 Byte) contains bits representing information on the content and format of the packet(s)
        self.datatype = None  #:(1 Byte) contains a value representing the type and format of the data
        self.relativetimecounter = None  #:(6 Bytes) contains a value representing the 10 MHz Relative Time Counter (RTC)
        self.ptptimeseconds = None  #: PTP Timestamp seconds
        self.ptptimenanoseconds = None  #: PTP Timestamp nanoseconds
        self.ts_source = "ieee1588" #:The timestamp source. Select from :attr:`Chapter10.TS_SOURCES`
        self.payload = ""  #:The payload
        self.data_checksum_size = 0
        self.filler = ""
        self._secondary_header = False

    @property
    def packetflag(self):
        """
        (1 Byte) contains bits representing information on the content and format of the packet(s)

        :type val: intx
        """
        return self._packetflag

    @packetflag.setter
    def packetflag(self, val):

        if val > 0xFF:
            raise Exception("Packet flag ={:#0X} to valuid".format(val))
        self._packetflag = val

        if self._packetflag >> 7 == 1:

            if ((self._packetflag >> 2) & 0x3) == 0:
                self.ts_source = "ch4"
            elif ((self._packetflag >> 2) & 0x3) == 1:
                self.ts_source = "ieee1588"
            else:
                raise Exception("Time format is illegal")

            self._secondary_header = True
        else:
            self._secondary_header = False

    def pack(self):
        """
        Pack the Chapter10 object into a binary buffer

        :rtype: str 
        """

        if self._secondary_header:
            if self.ts_source == "ch4":
                raise Exception("Ch4 Timestamp in secondary header not supported")

            sec_hdr = struct.pack(Chapter10.CH10_OPT_HDR_FORMAT, self.ptptimenanoseconds, self.ptptimeseconds, 0, 0)
            # Replace the checksum
            cs = get_checksum_buf(sec_hdr)
            sec_hdr = sec_hdr[:-2] + struct.pack("<H", cs)
        else:
            sec_hdr = ""

        total_len_excl_filler = len(sec_hdr) + len(self.payload) + Chapter10.CH10_HDR_FORMAT_LEN + self.data_checksum_size

        # Add the filler
        if total_len_excl_filler % 4 == 0:
            self.filler = ""
        else:
            fill_len = 4 - (total_len_excl_filler % 4)
            fill_val = [0xFF] * fill_len
            self.filler = struct.pack(">{}B".format(fill_len), *fill_val)

        self.packetlen = total_len_excl_filler + len(self.filler)
        self.datalen = len(self.payload)

        checksum = 0
        _rtc_lwr = self.relativetimecounter & 0xFFFFFFFF
        _rtc_upr = self.relativetimecounter >> 32

        hdr = struct.pack(Chapter10.CH10_HDR_FORMAT, self.syncpattern, self.channelID, self.packetlen, self.datalen,
                          self.datatypeversion, self.sequence, self.packetflag, self.datatype, _rtc_lwr,_rtc_upr, checksum)
        hdr = hdr[:-2] + struct.pack("<H", get_checksum_buf(hdr))
        return hdr + sec_hdr + self.payload + self.filler

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10 object

        :param buffer: A string buffer representing an Chapter10 packet
        :type buffer: str
        :rtype: None
        """
        (self.syncpattern, self.channelID, self.packetlen, self.datalen, self.datatypeversion, self.sequence,
         self.packetflag, self.datatype, _rtc_lwr,_rtc_upr, checksum) = struct.unpack_from(Chapter10.CH10_HDR_FORMAT, buffer)

        offset_hdr = struct.calcsize(Chapter10.CH10_HDR_FORMAT)-2
        exp_checksum = get_checksum_buf(buffer[:offset_hdr])
        #if checksum != exp_checksum:
        #    raise Exception("Ch10 Header checksum does not match expected={:#0X}".format(exp_checksum))

        self.relativetimecounter = _rtc_lwr + (_rtc_upr << 32)

        self.ts_source = "ieee1588"
        if (self.packetflag >> 7) == 1:
            self._secondary_header = True
            pkt_hdr_time =  (self.packetflag >> 2) & 0x3
            (ts_ns, ts_s, _res, _checksum_sec) = struct.unpack_from(
                Chapter10.CH10_OPT_HDR_FORMAT, buffer, Chapter10.CH10_HDR_FORMAT_LEN)

            sec_exp_checksum = get_checksum_buf(
                buffer[Chapter10.CH10_HDR_FORMAT_LEN:Chapter10.CH10_HDR_FORMAT_LEN+Chapter10.CH10_OPT_HDR_FORMAT_LEN-2])

            if _checksum_sec != sec_exp_checksum:
                raise Exception("Ch10 Secondary Header checksum does not match expected={:#0X}".format(sec_exp_checksum))

            if pkt_hdr_time == 0:
                raise Exception("Ch4 Timestamp in secondary header not supported")
            elif pkt_hdr_time == 1:
                self.ts_source = "ieee1588"
                self.ptptimenanoseconds = ts_ns
                self.ptptimeseconds = ts_s
            else:
                raise Exception("Secondary Header Time Format not legal")
            self.payload = buffer[(Chapter10.CH10_HDR_FORMAT_LEN + Chapter10.CH10_OPT_HDR_FORMAT_LEN):]
        else:
            self._secondary_header = False
            self.payload = buffer[Chapter10.CH10_HDR_FORMAT_LEN:]

        return True

    def __eq__(self, other):
        if not isinstance(other, Chapter10):
            return False

        _match_att = ("syncpattern", "channelID", "packetlen", "datalen", "datatypeversion", "datatype", "_packetflag",
                      "relativetimecounter", "ptptimeseconds", "ptptimenanoseconds", "ts_source", "payload",
                      "data_checksum_size", "filler", "_secondary_header")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "Chapter 10: ChannelID={} Sequence={} DataLen={}".format(self.channelID, self.sequence, self.datalen)


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
        exp_msg = (len(buffer) - CH_SPECIFIC_HDR_LEN) / ARINC_WORD_LEN
        for msg_idx in range(exp_msg):
            offset = (msg_idx * ARINC_WORD_LEN) + CH_SPECIFIC_HDR_LEN
            arinc_data = ARINC429DataWord()
            arinc_msg_word_buffer = buffer[offset:offset+ARINC_WORD_LEN]
            arinc_data.unpack(arinc_msg_word_buffer)
            self.arincwords.append(arinc_data)

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
        ret_str =  "ARINCPayload: MessageCount={}\n".format( self.msgcount)

        for a in self.arincwords:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.arincwords):
            _dw = self.arincwords[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    def __len__(self):
        return len(self.arincwords)

    def __getitem__(self, key):
        return self.arincwords[key]


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
        self.gaptime = None  #: The gap time from the beginning of the preceding bus word (regardless of bus) to the
        # beginning of the current bus word in 0.1-us increments
        self.format_error = False  #: Format error has occurred
        self.parity_error = False  #: Parity error has occurred
        self.bus_speed = ARINC429DataWord.LO_SPEED  #: Arinc bus speed
        self.bus = None  #: Bus number index from 0
        self.payload = ""  #: ARINC word as a string payload

    def pack(self):
        """
        Pack the ARINC-429 data packet object into a binary buffer

        :rtype: str 
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
        ( _gap, _flag, self.bus) = struct.unpack_from(ARINC429DataWord.HDR_FORMAT, buffer)
        self.payload = buffer[struct.calcsize(ARINC429DataWord.HDR_FORMAT):]
        self.format_error = bool((_flag >> 7) & 0x1)
        self.parity_error = bool((_flag >> 6) & 0x1)
        self.bus_speed = (_flag >> 6) & 0x1
        self.gaptime = (_flag << 16) + _gap

        return True

    def __eq__(self, other):
        if not isinstance(other, ARINC429DataWord):
            return False

        _match_att = ( "gaptime", "format_error", "parity_error", "bus_speed", "bus", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "ARINCData: GapTime={} FormatError={} ParityError={} BusSpeed={} Bus={}".format(
             self.gaptime, self.format_error, self.parity_error, self.bus_speed, self.bus)


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
        ret_buf = struct.pack("<I", int(ts_present) << 31)
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
        while offset < len(mybuffer):
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

        _match_att = ("uartwords")

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
        self.subchannel = None  #: Subchannel
        self.datalength = None  #: Data Length
        self._payload = ""  #: UART payload

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

        :rtype: str
        """
        if self.ptptimeseconds is not None and self.ptptimenanoseconds is not None:
            ch_spec_word = struct.pack("<II",self.ptptimenanoseconds, self.ptptimeseconds)
        else:
            ch_spec_word = ""
        data_len = len(self.payload)
        if self.parity_error:
            _subch = self.subchannel + 0x80
        else:
            _subch = self.subchannel
        intra_pkt_header = struct.pack("<HH", data_len, _subch)

        if data_len % 2 == 1:
            padding = struct.pack("B", 0xFF)
        else:
            padding = ""

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

        _match_att = ( "ptptimeseconds", "ptptimenanoseconds", "parity_error", "subchannel", "datalength", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "UARTDataWord: PTPSec={} PTPNSec={} ParityError={} DataLen={} SubChannel={}".format(
             self.ptptimeseconds, self.ptptimenanoseconds, self.parity_error, self.datalength, self.subchannel)
