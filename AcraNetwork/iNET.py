"""
.. module:: iNET
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct iNET Packets

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"

import struct


class iNETPackage(object):
    """
    The _payload of an iNET packet is multiple Package Headers. This class handles such objects
    """

    PKG_FORMAT = ">IHBBI"
    PKG_FORMAT_LEN = struct.calcsize(PKG_FORMAT)
    REQ_ATTR = ("definitionID", "flags", "timedelta", "payload")
    PAD_BYTE = b'\x00'

    def __init__(self):
        self.definitionID = None  #: Package definition ID
        self.flags = None  #: Package status Flags defined in the MDL document
        self._length = 0
        self.timedelta = 0  #: Package time relative to the parent Message timestamp in nanoseconds
        self.payload = b""  #: The package payload

    def pack(self):
        """
        Pack the packet into a binary format and return as a string

        :rtype: str
        """
        for attr in iNETPackage.REQ_ATTR:
            if getattr(self, attr) is None:
                raise ValueError("Require {} is not defined".format(attr))

        if len(self.payload) % 4 != 0:
            padding = (4-len(self.payload) % 4) * iNETPackage.PAD_BYTE
        else:
            padding = b""

        self._length = iNETPackage.PKG_FORMAT_LEN + len(self.payload)

        return struct.pack(iNETPackage.PKG_FORMAT, self.definitionID, self._length, 0, self.flags,  self.timedelta) + \
               self.payload + padding

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an iNET package.
        Accepts a buffer to unpack as the required argument. Returns the unused buffer so that the unpack method
        can be called repeatedly

        :param buf: The string buffer to unpack
        :type buf: str
        :rtype: str
        """
        (self.definitionID, self._length, _res, self.flags, self.timedelta) = \
            struct.unpack_from(iNETPackage.PKG_FORMAT, buf)
        self.payload = buf[iNETPackage.PKG_FORMAT_LEN:self._length]
        if self._length % 4 != 0:
            padding_len = 4 - (self._length % 4)
        else:
            padding_len = 0

        return buf[self._length + padding_len:]


class iNET(object):
    """ 
    Class to pack and unpack iNET payloads. iNET is standard packet format for use
    in FTI networks. It is usually transmitted in a UDP packet containing parameter data
    acquired from sensors and buses

    The packet structure is defined in IRIG106 Chapter24 http://www.irig106.org/docs/106-17/Chapter24.pdf
    
    Capture a UDP packet and unpack the _payload as an iNET packet

    >>> import socket
    >>>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = iNET()
    >>> i.unpack(data)
    >>> print i.definition_ID
    6
    >>> print i.packages[0].definitionID
    2

    :type flags: int
    :type type: int
    :type version: int
    :type definition_ID: int
    :type sequence: int
    :type ptptimeseconds: int
    :type ptptimenanoseconds: int
    :type app_fields: list[str]
    :type _payload: str
    :type packages: list[iNETPackage]
    """

    INET_HEADER_FORMAT = '>BBHIIIII'
    INET_HEADER_LENGTH = struct.calcsize(INET_HEADER_FORMAT)
    REQ_ATTR = ("flags", "type", "version", "definition_ID", "sequence", "ptptimeseconds", "ptptimenanoseconds",
                "app_fields", "_payload")

    def __init__(self):
        '''Creator method for an iNET class'''
        self.flags = None  #: Message Flags. Bits 15:8 Reserved.
        self.type = 0  #: Message type
        self._option_wc = 0
        self.version = 1  #: Message version
        self.definition_ID = None  #: Message Definition ID
        self.sequence = None  #: Message Sequence Number
        self._length = None  # Length in bytes including header and _payload
        self.ptptimeseconds = None  #: PTP timestamps in seconds
        self.ptptimenanoseconds = None  #: PTP timestamps in nanoseconds
        self.app_fields = []  #: Optional Application Defined fields.
        self._payload = None  # Payload
        self.packages = []  #: The payload is made up of packages. The packagaes are stored in this attribute list[:class:`iNETPackage`]

    def pack(self):
        """
        Pack the packet into a binary format and return as a string

        :rtype: str|bytes
        """

        _wc_ver = len(self.app_fields) + (self.version << 4)

        self._payload = b""
        for pkg in self.packages:
            self._payload += pkg.pack()

        for attr in iNET.REQ_ATTR:
            if getattr(self, attr) is None:
                raise ValueError("Attribute {} is not defined".format(attr))

        self._length = len(self._payload) + iNET.INET_HEADER_LENGTH + len(self.app_fields) * 4
        packet = struct.pack(iNET.INET_HEADER_FORMAT, _wc_ver, self.type, self.flags,  self.definition_ID,
                             self.sequence, self._length, self.ptptimeseconds, self.ptptimenanoseconds)
        if len(self.app_fields) > 0:
            packet += struct.pack(">{}I".format(len(self.app_fields)), *self.app_fields)

        packet += self._payload

        return packet

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an iNET object
        Accepts a buffer to unpack as the required argument

        :param buf: The string buffer to unpack
        :type buf: str
        :rtype: bool
        """

        if len(buf) < iNET.INET_HEADER_LENGTH:
            raise ValueError("Buffer is too short to be an iNET packet")

        (_wc_ver, _type, self.flags,  self.definition_ID, self.sequence, self._length, self.ptptimeseconds,
         self.ptptimenanoseconds) = struct.unpack_from(iNET.INET_HEADER_FORMAT, buf)
        self.type = _type & 0xF
        self._option_wc = _wc_ver & 0xF
        self.version = (_wc_ver >> 4) & 0xF

        if self._option_wc > 0:
            self.app_fields = list(struct.unpack_from(">{}I".format(self._option_wc), buf[iNET.INET_HEADER_LENGTH:]))

        self._payload = buf[iNET.INET_HEADER_LENGTH + (self._option_wc * 4):]

        package_buf = self._payload
        while len(package_buf) > 0:
            package = iNETPackage()
            package_buf = package.unpack(package_buf)
            self.packages.append(package)

        return True

    def __repr__(self):
        return "MessageDefinitionID={:#0X} Sequence={} Type={} TimeStamp(s)={} TimeStamp(ns)={} OptionWordCount={}".format(
            self.definition_ID, self.sequence, self.type, self.ptptimeseconds, self.ptptimenanoseconds, self._option_wc)

    def __eq__(self, other):
        if not isinstance(other, iNET):
            return False

        for attr in iNET.REQ_ATTR:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __len__(self):
        return len(self.pack())






