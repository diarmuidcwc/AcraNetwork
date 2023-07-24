import struct


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

    CH10_UDP_HEADER_FORMAT1 = '<BBH'
    CH10_UDP_HEADER_FORMAT2 = ">HBB"
    CH10_UDP_SEG_HEADER_FORMAT1 = '<HBBI'

    CH10_HDR_LEN = {1: 4, 2: 12, 3: 8}  # fmt1, 2, 3

    CH10_UDP_HEADER_LENGTH = struct.calcsize(CH10_UDP_HEADER_FORMAT1)
    CH10_UDP_SEG_HEADER_LENGTH = struct.calcsize(CH10_UDP_SEG_HEADER_FORMAT1)

    TYPE_FULL = 0  #: Full Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`
    TYPE_SEG = 1  #: Segmented Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`



    def __init__(self):
        '''Creator method for a UDP class'''
        self.version = 1  #: Version
        self.type = Chapter10UDP.TYPE_SEG  #: Type of message , Full or Segmented
        self.channelID = None  #: Segmented Packets Only. Channel ID of the data in the RCC 106 Chapter 10 packet
        self.channelsequence = None  #: Segmented Packets Only, Channel Sequence Number of the data in the RCC 106 Chapter 10 packet
        self.sequence = 0  #: UDP Sequence number
        self.segmentoffset = 0  #: Segmented Packets Only. The 32-bit Segmented Packets Only, Position of the data in the RCC 106 Chapter 10 packet.
        self.packetsize = None  #: Format 2 Packet size
        self.sourceid_len = 0  #: Format 3 Source ID length
        self.sourceid = 0  #: Format 3 Source ID
        self.offset_pkt_start = None  #: Format 3 Offset to packet start in bytes
        self.payload = b""

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10UDP object

        :param buffer: A string buffer representing an Chapter10UDP packet
        :type buffer: bytes
        :rtype: None
        """
        # Format 2 is big endian so check if this packet is format 2 first
        (seg_upr, seg_lwr, _ver_type) = struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT2, buffer)
        # Because of the endianness issue, some format 1 packets can look like format 2 if we naievly look at the
        # format field. Instead also look at the size and if it matches the size of the buffer then assume that
        # we have the correct format
        (_size_upp, _size_lower,) = struct.unpack_from(">BH", buffer, 5)
        size_guess = _size_lower + (_size_upp << 16)
        if _ver_type & 0xF in [1, 2, 3] and (_ver_type >> 4) & 0xF in [Chapter10UDP.TYPE_FULL, Chapter10UDP.TYPE_SEG]:
            self.version = _ver_type & 0xF
        else:
            (_ver_type, seg_lwr, seg_upr) = struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, buffer)
            self.version = _ver_type & 0xF

        self.type = _ver_type >> 4
        self.sequence = seg_lwr + (seg_upr << 8)

        if self.version == 3:
            self.sourceid_len =_ver_type >> 4
            self.offset_pkt_start = seg_upr

        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            (self.channelID, self.channelsequence, _res, self.segmentoffset) = \
                struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, buffer, Chapter10UDP.CH10_UDP_HEADER_LENGTH)
            self.payload = buffer[(Chapter10UDP.CH10_UDP_HEADER_LENGTH + Chapter10UDP.CH10_UDP_SEG_HEADER_LENGTH):]
        elif self.format == 1:
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH:]
        elif self.format == 2:

            (_segoffset_upper ,_size_upp, _size_lower , _segoff_lower, self.channelID) = struct.unpack_from(
                ">BBHHH", buffer, 4
            )
            self.packetsize = _size_lower + (_size_upp << 16)
            self.segmentoffset = _segoff_lower + (_segoffset_upper << 16)
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH + 8:]
        elif self.format == 3:
            (_srcid_datat, ) = struct.unpack_from("<I", buffer, 4)
            if self.sourceid_len == 0:
                self.sourceid = 0x0
                self.sequence = _srcid_datat
            elif self.sourceid_len == 1:
                self.sourceid = _srcid_datat >> (32 - 4)
                self.sequence = _srcid_datat & 0x0FFFFFFF
            elif self.sourceid_len == 2:
                self.sourceid = _srcid_datat >> (32 - 8)
                self.sequence = _srcid_datat & 0x00FFFFFF
            elif self.sourceid_len == 3:
                self.sourceid = _srcid_datat >> (32 - 12)
                self.sequence = _srcid_datat & 0x000FFFFF
            elif self.sourceid_len == 4:
                self.sourceid = _srcid_datat >> (32 - 16)
                self.sequence = _srcid_datat & 0x0000FFFF
            else:
                raise Exception("Source id length {} is not valid".format(self.sourceid_len))

            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH + 4:]

        else:
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH:]

        return True

    @property
    def format(self):
        return self.version

    @format.setter
    def format(self, val):
        self.version = val

    def pack(self):
        """
        Pack the Chapter10UDP object into a binary buffer

        :rtype: bytes
        """

        if self.format == 3:
            _ver_type = (self.sourceid_len << 4) + self.version
            seg_up = self.offset_pkt_start
            seg_lr = 0
        else:
            _ver_type = (self.type << 4) + self.version
            seg_up = self.sequence >> 8
            seg_lr = self.sequence & 0xFF

        if self.format == 2:
            _payload = struct.pack(Chapter10UDP.CH10_UDP_HEADER_FORMAT2, seg_up, seg_lr, _ver_type)
        else:
            _payload= struct.pack(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, _ver_type, seg_lr, seg_up)

        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            _payload += struct.pack(Chapter10UDP.CH10_UDP_SEG_HEADER_FORMAT1, self.channelID, self.channelsequence, 0, self.segmentoffset)

        elif self.format == 2:
            self.packetsize = len(self.payload)//4
            _payload += struct.pack(">BBHHH", self.segmentoffset >> 16, self.packetsize >> 16, self.packetsize & 0xFFFF, self.segmentoffset & 0xFFFF,
                                   self.channelID)

        elif self.format == 3:
            if self.sourceid_len == 0:
                _field = self.sequence
            elif self.sourceid_len == 1:
                _field = (self.sequence & 0x0FFFFFFF) + (self.sourceid << (32 - 4))
            elif self.sourceid_len == 2:
                _field = (self.sequence & 0x00FFFFFF) + (self.sourceid << (32 - 8))
            elif self.sourceid_len == 3:
                _field = (self.sequence & 0x000FFFFF) + (self.sourceid << (32 - 12))
            elif self.sourceid_len == 4:
                _field = (self.sequence & 0x0000FFFF) + (self.sourceid << (32 - 16))
            else:
                _field = 0
                raise Exception("Invalid source id")

            _payload += struct.pack("<I", _field)

        return _payload + self.payload

    def __repr__(self):
        if self.type == Chapter10UDP.TYPE_FULL:
            return "CH10 UDP Full Packet: Format={} Sequence={}".format(
                self.format, self.sequence)
        else:
            return "CH10 UDP Sequence: Format={} Sequence={} ChID={} ChSeqNum={} SegOffset={}".format(
                self.format, self.sequence, self.channelID, self.channelsequence, self.segmentoffset)

    def __eq__(self, other):
        if not isinstance(other, Chapter10UDP):
            return False

        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            _match_att = ("version", "type", "sequence", "channelID", "channelsequence", "segmentoffset", "payload")
        elif self.format == 2:
            _match_att = ("format", "type", "sequence", "channelID", "channelsequence", "segmentoffset", "packetsize",
                          "payload")
        elif self.format == 3:
            _match_att = ("format", "sourceid_len", "sourceid", "sequence", "offset_pkt_start", "payload")
        else:
            _match_att = ("version", "type", "sequence", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True