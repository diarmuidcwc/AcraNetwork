"""
.. module:: IENA
    :platform: Unix, Windows
    :synopsis: Class to pack and unpack IENA packets

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct
import datetime,time
from collections import namedtuple


class IENA (object):
    """
    Class to :meth:`IENA.pack` and :meth:`IENA.unpack` IENA payloads. 
    
    IENA is an proprietary payload format
    developed by Airbus for use in FTI networks. It is usually transmitted in a UDP packet
    containing parameter data acquired from sensors and buses::
    
        ---2B--- ---2B-- -----------6B----------- -1B- -1B- ---2B--- ------0B to 65490B----- ---2B---
        | KEY   | SIZE  | TIME SINCE START YR(US)| ST | N2 | SEQNUM |      PARAMETERS       |   END  |
        -------- ------- ------------------------ ---- ---- -------- ----------------------- --------  
    
    Create an IENA packet and return the packed buffer
    

    >>> i = IENA()
    >>> i.key = 0xDC
    >>> i.sequence = 1
    >>> i.endfield = 0xDEAD
    >>> i.keystatus = 0
    >>> i.status = 0x0
    >>> i.timeusec = int(10e6)
    >>> i.payload = struct.pack('H',0x5)
    >>> i.pack()
    b'\\x00\\xdc\\x00\\t\\x00\\x00\\x00\\x98\\x96\\x80\\x00\\x00\\x00\\x01\\x05\\x00\\xde\\xad'
    
    Read in some data stored in a UDP packet in a pcap file
    
    >>> import AcraNetwork.Pcap as pcap
    >>> p = pcap.Pcap("../test/iena_test.pcap")
    >>> rec_payload = p[0].payload
    >>> i = IENA()
    >>> i.unpack(rec_payload[0x2a:])  # Offset into the pcap record
    True
    >>> print("{:#0X}".format(i.key))
    0X1A

    :type key: int
    :type size: int
    :type timeusec: int
    :type keystatus: int
    :type status: int
    :type sequence: int
    :type endfield: int
    :type payload: bytes
     
    """
    IENA_HEADER_FORMAT = '>HHHIBBH'
    IENA_HEADER_LENGTH = struct.calcsize(IENA_HEADER_FORMAT)
    TRAILER_LENGTH = 2

    REQ_ATTR = ("key", "timeusec", "keystatus", "status", "sequence", "endfield", "payload")

    def __init__(self):

        self._key = None # know as ienakey
        self.size = None #: IENA packet size incl header. This is calculated automatically when packing the message
        self.timeusec = 0 #: Time of the first byte in the payload in us since Jan 1st of the current year
        self.keystatus = None  #: Key Status. Fully described in the IENA standard
        self.status = None #: N2 Status. Fully described in the IENA standard
        self.sequence = None #: Sequence Number. Circular counter unique per key. Wraps at 16 bits.
        self.endfield = 0xdead #: Trailer field in the IENA packet
        self.payload = None #: Payload of the IENA packet

        self._packetStrut = struct.Struct(IENA.IENA_HEADER_FORMAT)
        # only calculate this once TODO: This is wrong
        self._startOfYear = datetime.datetime(datetime.datetime.today().year, 1, 1, 0, 0, 0,0)
        self.lengthError = False # Flag to verify the buffer length

        # The required attributes
        self._req_attr = IENA.REQ_ATTR

    @property
    def key(self):
        """
        The IENA Key. Identifies the IENA packet type
        """
        return self._key

    @key.setter
    def key(self,key):
        self._key = key

    @property
    def streamid(self):
        """
        Alias of the IENA key.
        """
        return self._key

    @streamid.setter
    def streamid(self, key):
        self._key = key

    @property
    def n2(self):
        """
        Alias of the N2 Status.
        """
        return self.status

    @n2.setter
    def n2(self, n2):
        self.status = n2

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IENA object
        Accepts a buffer to unpack as the required argument
        
        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        # Some checking
        if len(buf) < IENA.IENA_HEADER_LENGTH:
            raise ValueError("Buffer passed to unpack is too small to be an IENA packet")

        (self.key, self.size, timehi, timelo, self.keystatus, self.status, self.sequence)  = self._packetStrut.unpack_from(buf)
        self.timeusec = timelo + timehi * 2**32

        if self.size*2 != len(buf):
            raise Exception("Length field does not match the size of the packet")

        self.payload = buf[IENA.IENA_HEADER_LENGTH:-2]
        (self.endfield,) = struct.unpack_from(">H",buf, -2) # last two bytes are the trailer

        return True

    def pack(self):
        """
        Pack the IENA payload into a binary string
        
        :rtype: bytes
        """

        for attr in self._req_attr:
            if getattr(self, attr) is None:
                raise ValueError("Require {} is not defined".format(attr))

        timehi = self.timeusec >> 32
        timelo = self.timeusec % 0x100000000

        self.size =  (len(self.payload)  + IENA.IENA_HEADER_LENGTH + IENA.TRAILER_LENGTH) // 2 # size is in words

        packetvalues = (self.key, self.size, timehi, timelo, self.keystatus, self.status, self.sequence)
        packet = self._packetStrut.pack(*packetvalues) + self.payload + struct.pack('>H', self.endfield)

        return packet

    def _getPacketTime(self):
        """
        Return the Packet time in standard UNIX time
        
        :rtype: int
        """
        return int(self.timeusec/1e6 + time.mktime(self._startOfYear.timetuple()))

    def setPacketTime(self, utctimestamp, microseconds=0):
        """ 
        Set the packet timestamp
        
        :param timestamp: The seconds timestamp based on he standard timeformat 
        :type timestamp: int
        :param microseconds: The microseconds part of the timestamp
        :type microseconds: int
        
        """
        seconds_this_year = utctimestamp - int(time.mktime(self._startOfYear.timetuple()))
        packettime = microseconds + int(seconds_this_year)*1000000
        self.timeusec = packettime

    def __repr__(self):
        return "IENAP: KEY={:#0X} SEQ={} TIMEUS={}".format(self.key, self.sequence, self.timeusec)

    def __eq__(self, other):

        for attr in self._req_attr:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __len__(self):
        return len(self.pack())


class MParameter(namedtuple("MParameter", "paramid, delay, dataset")):
    """
    The MParameter is a object representing each MParameter in an IENA-M packet

    :param paramid: The param ID for this parameter
    :type paramid: int
    :param delay: The delay for this parameter
    :type delay: int
    :param dataset: The dataset payload as a string
    :type dwords: bytes
    """

    def __repr__(self):
        return "ParamID={:#0X} Delay={} Dataset Length={}".format(self.paramid, self.delay, len(self.dataset))


class IENAM(IENA):
    """
    Support for IENA-M packets. Message Parameters with delay field
    
    This payload includes a defined parameter ID, a delay and a length field
    
    All this is encapsulated inside an IENA packet as defined above::
    
        ---2B--- ---2B-- ---2B--- ------0B to 65490B----------
        |PARAM  | DELAY | LENGTH | Dataset with opt 1B pad    |
        -------- ------- -------------------------------------  
    
    Unpack some received packet from the network
    
    >>> import socket
    >>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = IENAM()
    >>> i.unpack(data)
    >>> for param in i:
    ...   print param.paramid
    6
    
    """

    _FORMAT_ = ">HHH"
    _FORMAT_LEN_ = struct.calcsize(_FORMAT_)
    REQ_ATTR = ("key", "timeusec", "keystatus", "status", "sequence", "endfield", "payload", "parameters")

    def __init__(self):
        IENA.__init__(self)
        self.parameters = []  #: The list of all MParameters in thie IENA-M packet Each entry is of class :class:`MParameter`
        self._req_attr = IENAM.REQ_ATTR

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IENA-M object
        Accepts a buffer to unpack as the required argument

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        super(IENAM, self).unpack(buf)
        remaining_payload = self.payload

        while len(remaining_payload) > 0:
            (_paramid, _delay, datasetlength) = struct.unpack(
                IENAM._FORMAT_, remaining_payload[:IENAM._FORMAT_LEN_])
            # Check if we have enough payload
            if len(self.payload[IENAM._FORMAT_LEN_:]) < datasetlength:
                raise Exception("M Param dataset length {} larger than payload{}".format(
                    datasetlength, len(remaining_payload[IENAM._FORMAT_LEN_:])))

            mparam = MParameter(paramid=_paramid, delay=_delay,
                                dataset=remaining_payload[IENAM._FORMAT_LEN_:IENAM._FORMAT_LEN_+datasetlength])
            self.parameters.append(mparam)
            if datasetlength % 2 == 1:
                padding = 1
            else:
                padding = 0
            remaining_payload = remaining_payload[IENAM._FORMAT_LEN_+datasetlength+padding:]

    def pack(self):
        """
        Pack the IENA-M payload into a binary string

        :rtype: bytes
        """
        self.payload = b""
        for mparam in self:
            datasetlength = len(mparam.dataset)
            self.payload += struct.pack(IENAM._FORMAT_, mparam.paramid, mparam.delay, datasetlength)
            self.payload += mparam.dataset
            if datasetlength % 2 == 1:
                self.payload += struct.pack(">B", 0)

        return super(IENAM, self).pack()

    def __repr__(self):
        txt= "IENAM: KEY={:#0X} SEQ={} TIMEUS={} NUM_MPARAM={}\n".format(self.key, self.sequence, self.timeusec,
                                                                         len(self))
        for idx, param in enumerate(self):
            txt += " M-Param #{}:{}\n".format(idx, repr(param))

        return txt

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.parameters):
            _param = self.parameters[self._index]
            self._index += 1
            return _param
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.parameters)

    def __getitem__(self, key):
        return self.parameters[key]


class QParameter(namedtuple("QParameter", "paramid, dataset")):
    """
    The QParameter is a object representing each QParameter in an IENA-Q packet

    :param paramid: The param ID for this parameter
    :type paramid: int
    :param dataset: The dataset payload as a string
    :type dwords: bytes
    """

    def __repr__(self):
        return "ParamID={:#0X} Dataset Length={}".format(self.paramid, len(self.dataset))


class IENAQ(IENA):
    """
    Support for IENA-Q packets. Message Parameters without delay field

    This payload includes a defined parameter ID and a length field

    All this is encapsulated inside an IENA packet as defined above::

        ---2B---  ---2B--- ------0B to 65490B----------
        |PARAM   | LENGTH | Dataset with opt 1B pad    |
        --------  ------- -----------------------------

    Unpack some received packet from the network

    >>> import socket
    >>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = IENAQ()
    >>> i.unpack(data)
    >>> for param in i:
    ...   print param.paramid
    6

    """

    _FORMAT_ = ">HH"
    _FORMAT_LEN_ = struct.calcsize(_FORMAT_)
    REQ_ATTR = ("key", "timeusec", "keystatus", "status", "sequence", "endfield", "payload", "parameters")

    def __init__(self):
        IENA.__init__(self)
        self.parameters = []  #: The list of all QParameters in thie IENA-Q packet Each entry is of class :class:`QParameter`
        self._req_attr = IENAM.REQ_ATTR

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IENA-Q object
        Accepts a buffer to unpack as the required argument

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        super(IENAQ, self).unpack(buf)
        remaining_payload = self.payload

        while len(remaining_payload) > 0:
            (_paramid, datasetlength) = struct.unpack(
                IENAQ._FORMAT_, remaining_payload[:IENAQ._FORMAT_LEN_])
            # Check if we have enough payload
            if len(self.payload[IENAQ._FORMAT_LEN_:]) < datasetlength:
                raise Exception("Q Param dataset length {} larger than payload{}".format(
                    datasetlength, len(remaining_payload[IENAQ._FORMAT_LEN_:])))

            qparam = QParameter(paramid=_paramid,
                                dataset=remaining_payload[IENAQ._FORMAT_LEN_:IENAQ._FORMAT_LEN_ + datasetlength])
            self.parameters.append(qparam)
            if datasetlength % 2 == 1:
                padding = 1
            else:
                padding = 0
            remaining_payload = remaining_payload[IENAQ._FORMAT_LEN_ + datasetlength + padding:]

    def pack(self):
        """
        Pack the IENA-Q payload into a binary string

        :rtype: bytes
        """
        self.payload = b""
        for qparam in self:
            datasetlength = len(qparam.dataset)
            self.payload += struct.pack(IENAQ._FORMAT_, qparam.paramid, datasetlength)
            self.payload += qparam.dataset
            if datasetlength % 2 == 1:
                self.payload += struct.pack(">B", 0)

        return super(IENAQ, self).pack()

    def __repr__(self):
        txt = "IENAQ: KEY={:#0X} SEQ={} TIMEUS={} NUM_QPARAM={}\n".format(self.key, self.sequence, self.timeusec, len(self))
        for idx, param in enumerate(self):
            txt += " Q-Param #{}:{}\n".format(idx, repr(param))

        return txt

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.parameters):
            _param = self.parameters[self._index]
            self._index += 1
            return _param
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.parameters)

    def __getitem__(self, key):
        return self.parameters[key]

class DParameter(namedtuple("DParameter", "paramid, delay, dwords")):
    """
    The DParameter is a object representing each DParameter in an IENA-D packet

    :param paramid: The param ID for this parameter
    :type paramid: int
    :param delay: The delay for this parameter
    :type delay: int
    :param dwords: List of all the d-words in the parameter
    :type dwords: list[int]
    """


class IENAD(IENA):
    """
    Support for IENA-D packets. Std parameters with delay field

    This payload includes a defined parameter ID, a delay and a length field

    All this is encapsulated inside an IENA packet as defined above with this pattern repeated
    
    The number of D-words are defined in the N2 field of the IENA header::

        ---2B--- ---2B-- ---2B--- ---2B---- ---2B--- ---2B---
        |PARAM  | DELAY | D#N    | D#-1    | ...    | D0     |
        -------- ------- ------------------------------------  

    Unpack some received packet from the network

    >>> import socket
    >>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = IENAD()
    >>> i.unpack(data)
    >>> print len(i.parameters)
    6

    :type parameters: list[DParameter]
    """

    _FORMAT_ = ">HHH"
    REQ_ATTR = ("key", "timeusec", "keystatus", "status", "sequence", "endfield", "payload", "parameters")

    def __init__(self):
        IENA.__init__(self)
        self.parameters = []  #: The list of all DParameters in thie IENA-D packet Each entry is of class :class:`DParameter`
        self._req_attr = IENAD.REQ_ATTR

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IENA-M object
        Accepts a buffer to unpack as the required argument

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        super(IENAD, self).unpack(buf)

        #According to the IENA spec,the N2 field contains the numner of data words
        dataword_count = self.keystatus & 0x7
        len_param_bytes = dataword_count * 2 + 4 # how big is each parameter grouping
        num_params = len(self.payload) // len_param_bytes  # So how many in the payload
        if len(self.payload) - (num_params * len_param_bytes) != 0:
            raise ValueError("There are not an integer number of D Parameters in the payload. Length DParam={} "
                            "Length IENA Payload={}".format(len_param_bytes, len(self.payload)))

        # Loop through
        for param in range(num_params):
            try:
                _dparams = struct.unpack_from(">{}H".format(dataword_count+2), self.payload, param*len_param_bytes)
            except Exception as e:
                raise IndexError("Could not unpack the payload from offset {}. Is the N2 field correct? "
                                "Expected {} data words. Error={}".format(dataword_count, param*len_param_bytes, e))
            dparam = DParameter(paramid=_dparams[0], delay=_dparams[1], dwords=list(_dparams[2:]))
            self.parameters.append(dparam)

    def __repr__(self):
        return "IENAD: KEY={:#0X} SEQ={} TIMEUS={} NUM_DPARAM={}".format(
            self.key, self.sequence, self.timeusec, len(self.parameters))

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.parameters):
            _param = self.parameters[self._index]
            self._index += 1
            return _param
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.parameters)

    def __getitem__(self, key):
        return self.parameters[key]


class NParameter(namedtuple("NParameter", "paramid, dwords")):
    """
    The NParameter is a object representing each NParameter in an IENA-N packet
    
    :param paramid: The param ID for this parameter
    :type paramid: int
    :param dwords: List of all the d-words in the parameter
    :type dwords: list[int]
    """


class IENAN(IENA):
    """
    Support for IENA-N packets. Std parameters without delay field

    This payload includes a defined parameter ID and payload

    All this is encapsulated inside an IENA packet as defined above with this pattern repeated
    
    The number of D-words are defined in the N2 field of the IENA header::

        ---2B--- ---2B-- ---2B--- ---2B---- ---2B--- ---2B---
        |PARAM  | D#N   | D#N-1  |   D#-1  | ...    | D0     |  
        -------- ------- ------------------------------------  

    Unpack some received packet from the network

    >>> import socket
    >>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> i = IENAN()
    >>> i.unpack(data)
    >>> print len(i.parameters)
    6
    >>> print i.parameters[0].paramid
    >>>
    4

    :type parameters: list[NParameter]
    
    """

    _FORMAT_ = ">HHH"
    REQ_ATTR = ("key", "timeusec", "keystatus", "status", "sequence", "endfield", "payload", "parameters")

    def __init__(self):
        IENA.__init__(self)
        self.parameters = []  #: List of all N-type parameters. Each entry is of class :class:`NParameter`
        self._req_attr = IENAN.REQ_ATTR

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IENA-M object
        Accepts a buffer to unpack as the required argument

        :param buf: The string buffer to unpack
        :type buf: bytes

        :rtype: bool
        """

        super(IENAN, self).unpack(buf)

        #According to the IENA spec,the N2 field contains the numner of data words
        dataword_count = self.keystatus & 0x7
        len_param_bytes = dataword_count * 2 + 2 # how big is each parameter grouping
        num_params = len(self.payload) // len_param_bytes  # So how many in the
        # Check that we don't have od
        if len(self.payload) - (num_params * len_param_bytes) != 0:
            raise ValueError("There are not an integer number of N Parameters in the payload. Length NParam={} "
                            "Length IENA Payload={}".format(len_param_bytes, len(self.payload)))

        # Loop through
        for param in range(num_params):
            try:
                _nparams = struct.unpack_from(">{}H".format(dataword_count+1), self.payload, param*len_param_bytes)
            except Exception as e:
                raise IndexError("Could not unpack the payload from offset {}. Is the N2 field correct? "
                                "Expected {} data words. Error={}".format(dataword_count, param*len_param_bytes, e))
            nparam = NParameter(paramid=_nparams[0], dwords=list(_nparams[1:]))
            self.parameters.append(nparam)

    def __repr__(self):
        return "IENAN: KEY={:#0X} SEQ={} TIMEUS={} NUM_DPARAM={}".format(
            self.key, self.sequence, self.timeusec, len(self))

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.parameters):
            _param = self.parameters[self._index]
            self._index += 1
            return _param
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.parameters)

    def __getitem__(self, key):
        return self.parameters[key]
