"""
.. module:: SimpleEthernet
    :platform: Unix, Windows
    :synopsis: A very trimmed down set of classes to unpack the common network packet formats

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct
import socket
from functools import reduce
from zlib import crc32


def unpack48(x):
    """
    Unpack a 48bit string returning an integer

    :param x: 6 byte buffer
    :type x: bytes

    :rtype: int 
    """
    x2, x3 = struct.unpack('>HI', x)
    return x3 | (x2 << 32)


def mactoreadable(macaddress):
    """
    Convert a macaddress into the readable form
    
    :param macaddress: The mac address in integer format
    :type macaddress: int
    
    :rtype: str
    """
    mac_string = ""
    b = []
    for i in range(6):
        eachbyte = (macaddress >> i*8) & 0xFF
        b.append(eachbyte)

    return "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}".format(b[5], b[4], b[3], b[2],  b[1], b[0])


def ip_calc_checksum(pkt):
    """
    Calculate the checksum of a packet
    
    :param pkt: The IP packet header packed into bytes
    :type pkt: str|bytes
    :return: 
    """

    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(struct.unpack("<{}H".format(len(pkt) // 2), pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff


def combine_ip_fragments(packets):
    """
    Combine the lists of fragmented IP packets into one IP packet

    :type packets: list[IP]
    :rtype: IP
    """
    ident = None
    # Check first the we have the correct imput
    for packet in packets:
        if not isinstance(packet, IP):
            raise Exception("packet is not of type IP")
        if ident is not None:
            if packet.id != ident:
                raise Exception("All packets should have the same ID field")
        ident = packet.id

    # Create the IP packet we will return
    combined_ip = IP()
    combined_ip.flags = 0x0
    combined_ip.fragment_offset = 0x0
    combined_ip.payload = bytes()
    # Create the header from the first fragment. Order the packets via the fragment offsets
    # I don't verify the offsets but blindly combine them. TODO: Improve
    for idx, packet in enumerate(sorted(packets, key=lambda x: x.fragment_offset)):
        if idx == 0:
            for attr in ["srcip", "dstip", "protocol", "version", "ihl", "dscp", "id", "ttl"]:
                setattr(combined_ip, attr, getattr(packet, attr))
        # Add the payload
        combined_ip.payload += packet.payload

    # Return the IP packet
    return combined_ip


class Ethernet(object):
    """
    This is simple class to pack or unpack an Ethernet packet. Handles very basic packets that are used in FTI
    
    Read an Ethernet Packet from a pcap file
    
    >>> import AcraNetwork.Pcap as Pcap
    >>> p = Pcap.Pcap("test_input.pcap")
    >>> mypcaprecord = p[0]
    >>> e = Ethernet()
    >>> e.unpack(mypcaprecord.packet)
    >>> print e
    SRCMAC=00:18:F8:B8:44:54 DSTMAC=E0:F8:47:25:93:36 TYPE=0X800
    
    :type type: int
    :type srcmac: int
    :type dstmac: int
    :type payload: bytes
    
    """
    HEADERLEN = 14
    HEADERLEN_VLAN = 18
    TYPE_IP = 0x800
    TYPE_IPv4 = 0x800  #:(Object Constant) IPv4 Type Constant
    TYPE_IPv6 = 0x86DD  #:(Object Constant) IPv6 Type Constant
    TYPE_ARP = 0x806   #:(Object Constant) ARP Type Constant
    TYPE_PAUSE = 0x8808   #:(Object Constant) PAUSE Type Constant
    TYPE_VLAN = 0x8100

    def __init__(self, buf=None):

        """
        Create an Ethernet packet object. 

        :param buf: If a buffer is passed in to the init method, it will be unpacked as a Ethernet packet
        :type buf: bytes

        """
        self.type = Ethernet.TYPE_IP #: The Ethertype field. Assign using the TYPE_* constants. https://en.wikipedia.org/wiki/EtherType
        self.srcmac = None #: The Ethernet source MAC Address. This is encoded into a 48bit field. https://en.wikipedia.org/wiki/MAC_address
        self.dstmac = None #: The Ethernet destination MAC Address. This is encoded into a 48bit field. https://en.wikipedia.org/wiki/MAC_address
        self.payload = None #: The Ethernet payload. Typically an IP packet.
        self.vlan = False
        self.vlantag = 0xFFFF

        if buf is not None:
            self.unpack(buf)

    def unpack(self, buf, fcs=False):
        """
        Unpack a raw byte stream to an Ethernet object

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        self.dstmac = unpack48(buf[:6])
        self.srcmac = unpack48(buf[6:12])
        (self.type,) = struct.unpack_from('>H',buf,12)
        if fcs:
            self.payload = buf[Ethernet.HEADERLEN:-4]
            _fcs_buf = buf[-4:]
            exp_crc = crc32(buf[:-4]) & 0xffffffff
            (act_crc,) = struct.unpack("I", _fcs_buf)
            if exp_crc != act_crc:
                raise Exception("FCS is wrong. Exo={:#0X} Act={:#0X}".format(exp_crc, act_crc))
        else:
            self.payload = buf[Ethernet.HEADERLEN:]
        return True

    def pack(self, fcs=False):
        """
        Pack the Ethernet object into a buffer
        
        :rtype: bytes
        """
        if self.dstmac == None or self.srcmac == None or self.type == None or self.payload == None:
            raise ValueError("All three required Ethernet fields are not complete")
        if self.vlan:
            header = struct.pack('>HIHIHHH',(self.dstmac>>32),(self.dstmac&0xffffffff),(self.srcmac>>32),(self.srcmac&0xffffffff), Ethernet.TYPE_VLAN, self.vlantag, self.type)
        else:
            header = struct.pack('>HIHIH',(self.dstmac>>32),(self.dstmac&0xffffffff),(self.srcmac>>32),(self.srcmac&0xffffffff), self.type)

        if fcs:
            _crc = crc32(header + self.payload) & 0xffffffff
            return header + self.payload + struct.pack("I", _crc)
        else:
            return header + self.payload

    def __repr__(self):
        return "SRCMAC={} DSTMAC={} TYPE={:#0X}".format(mactoreadable(self.srcmac), mactoreadable(self.dstmac), self.type)

    def __eq__(self, other):
        if not isinstance(other, Ethernet):
            return False

        for attr in ["type", "dstmac", "srcmac", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True


class IP(object):
    """
    Create or unpack an IP packet https://en.wikipedia.org/wiki/IPv4#Header
    
    If you wanted to unpack an Ethernet object payload which contains an IP packet
    
    >>> i = IP()
    >>> i.unpack(eth_pkt.payload)
    
    :type srcip: str
    :type dstip: str
    :type len: int
    :type flags: int
    :type protocol: int
    :type payload: bytes
    :type version: int
    :type ihl: int
    :type dscp: int
    :type id: int
    :type ttl: int
    
    """

    PROTOCOL_ICMP = 0x01  #:(Object Constant) ICMP Protocol Constant
    PROTOCOL_IGMP = 0x02  #:(Object Constant) IGMP Protocol Constant
    PROTOCOL_TCP = 0x6  #:(Object Constant) TCP Protocol Constant
    PROTOCOL_UDP = 0x11  #:(Object Constant) UDP Protocol Constant
    FLAG_DONT_FRAGMENT = 0x2
    FLAG_MORE_FRAGMENTS = 0x1

    PROTOCOLS = {"ICMP":PROTOCOL_ICMP, "IGMP" : PROTOCOL_IGMP, "TCP":PROTOCOL_TCP, "UDP":PROTOCOL_UDP}  #:(Object Constant) Protocols available
    IP_HEADER_FORMAT = '>BBHHBBBBHII'
    IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)

    def __init__(self, buf=None):
        """
        Create an IP packet object. Currently supports only IPv4
        
        :param buf: If a buffer is passed in to the init method, it will be unpacked as a IP packet
        :type buf: bytes
        
        """
        self.srcip = None #: Source IP Address
        self.dstip = None #: Destination IP Address
        self.len = None #: Total Length. This is calculated when packing the packet
        self.flags = 0x0 #: Three bit field identifying a flag
        self.fragment_offset = None #: Fragment offset
        self.protocol = IP.PROTOCOL_UDP #: The type of the payload
        self.payload = None #: The IPv4 payload
        self.version = 4 #: IP version field
        self.ihl = 5 #: Header length in 32 bit words
        self.dscp = 0 #: Differentiated Services Code Point
        self.id = 0 #: Identification Field
        self.ttl = 20 #: Time to Live. In practice the hop count.
		
        if buf is not None:
            self.unpack(buf)

    def unpack(self, buf):
        """
        Unpack a raw byte stream to an IP object

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """
        if len(buf) < IP.IP_HEADER_SIZE:
            raise ValueError("Buffer too short for to be an IP packet")
        (na1, self.dscp, self.len, self.id, self.flags, na3, self.ttl, self.protocol, checksum, self.srcip, self.dstip) \
            = struct.unpack_from(IP.IP_HEADER_FORMAT,buf)
        self.fragment_offset = (((self.flags & 0x1f) << 8) + na3) * 8 
        self.flags = self.flags >> 5
        self.version = na1 >> 4
        self.ihl = na1 & 0xf
        self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
        self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
        # Fill IP payload with number of bytes declared in header's length field, leaving any trailer behind (e.g. typically padding to reach 64bytes)
        self.payload = buf[IP.IP_HEADER_SIZE:self.len]

        return True

    def pack(self):
        """
        Pack the IP object into a buffer
        
        :rtype: bytes
        """

        for word in [self.dscp,self.id,self.flags,self.ttl,self.protocol,self.srcip,self.dstip]:
            if word is None:
                raise ValueError("All required IP payloads not defined")

        (srcip_as_int,) = struct.unpack('!I',socket.inet_aton(self.srcip))
        (dstip_as_int,) = struct.unpack('!I',socket.inet_aton(self.dstip))
        self.len = IP.IP_HEADER_SIZE+len(self.payload)
        header = struct.pack(IP.IP_HEADER_FORMAT, 0x45, self.dscp, self.len, self.id, self.flags, 0, self.ttl,
                             self.protocol, 0, srcip_as_int,dstip_as_int)
        checksum = ip_calc_checksum(header)
        header = header[:10] + struct.pack('H',checksum) + header[12:]
        return header + self.payload

    def __repr__(self):
        protocol = ""
        for p,v in IP.PROTOCOLS.items():
            if v == self.protocol:
                protocol = p
        return "SRCIP={} DSTIP={} PROTOCOL={} LEN={}".format(self.srcip, self.dstip, protocol, self.len)


class IPv6(object):
    """
    Create an IPv6 packet https://en.wikipedia.org/wiki/IPv6_packet

    :type version
    :type traffic_class
    :type flow_label
    :type len
    :type next_header
    :type hop_limit
    :type srcip
    :type dstip
    
    """

    PROTOCOL_ICMP = 0x01  #:(Object Constant) ICMP Protocol Constant
    PROTOCOL_IGMP = 0x02  #:(Object Constant) IGMP Protocol Constant
    PROTOCOL_TCP = 0x6  #:(Object Constant) TCP Protocol Constant
    PROTOCOL_UDP = 0x11  #:(Object Constant) UDP Protocol Constant
    FLAG_DONT_FRAGMENT = 0x2
    FLAG_MORE_FRAGMENTS = 0x1

    PROTOCOLS = {"ICMP":PROTOCOL_ICMP, "IGMP" : PROTOCOL_IGMP, "TCP":PROTOCOL_TCP, "UDP":PROTOCOL_UDP}  #:(Object Constant) Protocols available
    IP_HEADER_FORMAT = '>IHBBIIIIIIII'
    IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)

    def __init__(self, buf=None):
        """
        
        :param buf: If a buffer is passed in to the init method, it will be unpacked as a IP packet
        :type buf: bytes
        
        """
        self.version = 0x6 #: IP version field
        self.traffic_class = 0x00
        self.flow_label = 0x00000
        self.len = None #: Total Length. This is calculated when packing the packet
        self.next_header = 0x3B # 0x3B = No next header
        self.hop_limit = 0x01
        self.srcip = None #: Source IP Address
        self.dstip = None #: Destination IP Address
        self.payload = bytes()

        if buf is not None:
            self.unpack(buf)

    def pack(self):
        """
        Pack the IP object into a buffer
        
        :rtype: bytes
        """

        for word in [self.srcip,self.dstip]:
            if word is None:
                raise ValueError("All required IP payloads not defined")

        self.len = len(self.payload)
        header = struct.pack(IPv6.IP_HEADER_FORMAT, ((self.version<<28)+(self.traffic_class<<24)+self.flow_label), self.len, self.next_header, self.hop_limit, self.srcip>>96, (self.srcip>>64)&0xFFFFFFFF,(self.srcip>>32)&0xFFFFFFFF, self.srcip&0xFFFFFFFF, self.dstip>>96, (self.dstip>>64)&0xFFFFFFFF,(self.dstip>>32)&0xFFFFFFFF, self.dstip&0xFFFFFFFF)

        return header + self.payload

    def unpack(self, buffer):
        raise Exception("Not implemented")


    def __repr__(self):
        protocol = ""
        for p,v in IPv6.PROTOCOLS.items():
            if v == self.protocol:
                protocol = p
        return "SRCIP={} DSTIP={} PROTOCOL={} LEN={}".format(self.srcip, self.dstip, protocol, self.len)


class UDP(object):
    """
    Class to build and unpack a UDP packet
    
    https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
    
    Packet structure::
    
        -----2B----- -----2B----- -----2B----- -----2B----- --0-65527B----
        | SRC PORT  |  DEST PORT |   LENGTH   | CHECKSUM   | PAYLOAD
        ------------ ------------ ------------ ------------ --------------
    
    Create a UDP packet
    
    >>> u = UDP()
    >>> u.dstport = 5500
    >>> u.srcport = 4400
    >>> u.payload = struct.pack('B',0x5)
    >>> mypacket = u.pack()
    
    :type srcport: int
    :type dstport: int
    :type len: int
    :type payload: bytes
    """


    UDP_HEADER_FORMAT = '>HHHH'
    UDP_HEADER_SIZE = struct.calcsize(UDP_HEADER_FORMAT)

    def __init__(self, buf=None):

        self.srcport = None #: The UDP source port number
        self.dstport = None #: The UDP desitnation port number
        self.len = None #: The length of the UDP header and payload in bytes
        self.payload = None #: The UDP payload

        if buf is not None:
            self.unpack(buf)

    def unpack(self,buf):
        """
        Unpack a raw byte stream to a UDP object

        :param buf: The string buffer to unpack
        :type buf: bytes
        :rtype: bool
        """

        if len(buf) < UDP.UDP_HEADER_SIZE:
            raise ValueError("Buffer too short to be a UDP packet")
        (self.srcport,self.dstport,self.len,checksum) = struct.unpack_from(UDP.UDP_HEADER_FORMAT,buf)
        self.payload = buf[UDP.UDP_HEADER_SIZE:]

        return True

    def pack(self):
        """
        Pack the UDP object into a buffer
        
        :rtype: bytes
        """

        if self.srcport == None or self.dstport == None or self.payload == None:
            raise ValueError("All UDP fields need to be defined to pack the payload")

        self.len = len(self.payload) + UDP.UDP_HEADER_SIZE
        return struct.pack(UDP.UDP_HEADER_FORMAT,self.srcport,self.dstport,self.len,0) + self.payload

    def __repr__(self):
        return "SRCPORT={} DSTPORT={}".format(self.srcport, self.dstport)


class AFDX(object):
    """
    This class will  unpack an AFDX packet
    
    """

    HEADERLEN = 14
    DSTMAC_CONST = 0x3000000
    SRCMAC_CONST = 0x20000
    MIN_PAYLOAD_LEN = 42

    def __init__(self, buf=None):
        raise Exception("No working")
        self.type =None
        self.networkID = None
        self.equipmentID = None
        self.interfaceID = None
        self.vlink = None

        self.payload = None
        self.sequencenum = None
        if buf is not None:
            self.unpack(buf)

    def unpack(self, buf):
        self.set_dstmac(buf[:6])
        self.unpacksrcmac(unpack48(buf[6:12]))

        (self.type,) = struct.unpack_from('>H',buf,12)
        self.payload = buf[AFDX.HEADERLEN:-1]
        self.sequencenum = struct.unpack('B',buf[-1])

    def unpacksrcmac(self, mac):
        srcconstantf = mac >> 24
        #if srcconstantf != AFDX.SRCMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in SrcMac Address'.format(AFDX.SRCMAC_CONST))
        #(self.networkID,self.equipmentID,self.interfaceID) = struct.unpack_from('BBB',mac[:3])
        #self.interfaceID = self.interfaceID >> 5

    def set_dstmac(self, mac):
        (dstconstantf, vlink) = struct.unpack_from('>IH',mac)
        #if dstconstantf != AFDX.DSTMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in DestMac Address'.format(AFDX.DSTMAC_CONST))
        self.vlink = vlink

    def pack(self):

        if len(self.payload) < AFDX.MIN_PAYLOAD_LEN:
            raise ValueError('Minimum Payload of {} bytes'.format(AFDX.MIN_PAYLOAD_LEN))

        afdx_header = struct.pack('>IHHBBBBH',AFDX.DSTMAC_CONST, self.vlink, (AFDX.SRCMAC_CONST >> 8), 0, self.networkID,
                                  self.equipmentID, (self.interfaceID << 5), self.type)

        packet = afdx_header + self.payload + struct.pack('>B',self.sequencenum)

        return packet

    def __eq__(self, other):
        if not isinstance(other, AFDX):
            return False

        for attr in ["type", "networkID", "interfaceID", "equipmentID", "vlink", "sequencenum", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True


class ICMP(object):
    """
    ICMP packets.
    """

    TYPE_REPLY = 0x0
    TYPE_UNREACHABLE = 0X1
    TYPE_REDIRECT = 0X5
    TYPE_REQUEST = 0X8

    def __init__(self):
        self.type = None
        self.code = None
        self.request_id = None
        self.request_sequence = None
        self.payload = bytes()

    def pack(self):
        """
        Pack an ICMP object into a buff
        :return:
        """
        for attr in ("type", "code", "request_id", "request_sequence"):
            if type(getattr(self, attr)) != int:
                raise ValueError("Attribute {} is not an integer".format(attr))

        _hdr_no_checksum = struct.pack(">BBHHH", self.type, self.code, 0, self.request_id, self.request_sequence)
        _icmp_checksum = ip_calc_checksum(_hdr_no_checksum + self.payload)
        _hdr = _hdr_no_checksum[:2] + struct.pack('H', _icmp_checksum) + _hdr_no_checksum[4:]
        return _hdr + self.payload

    def unpack(self, buffer):
        raise NotImplementedError("Not implemented")


MOD = 1 << 16


def ones_comp_add16(num1,num2):
    result = num1 + num2
    return result if result < MOD else (result+1) % MOD


class IGMPv3(object):
    """
    Simplified IGMP
    """
    TYPE_QUERY = 0x11
    TYPE_MEMBERSHIP_REPORT = 0x22
    TYPE_REC_CHG_TO_EXCL_MODE = 4
    TYPE_REC_MODE_IS_EXCLUDE = 2

    IP_ADDR_QUERY = "224.0.0.1"
    IP_ADDR_JOIN = "224.0.0.22"
    MAC_ADDR = {IP_ADDR_QUERY: 0x1005e000001, IP_ADDR_JOIN: 0x1005e000016}

    def __init__(self):
        pass

    @staticmethod
    def membership_query():
        """
        Return a membership query
        :return:
        """
        query_type = 0x11
        max_resp_time_2p4s = 0x18
        cksum = 0xecd3
        mc_addr = "0.0.0.0"
        sts = 0x2
        qqic = 0x20
        num_src = 0x0
        return struct.pack(">BBH", query_type, max_resp_time_2p4s, cksum) + \
                socket.inet_aton(mc_addr) + struct.pack(">BBH", sts, qqic, num_src)

    @staticmethod
    def join_groups(groups):
        """
        Join the specified groups
        :param groups:
        :return: bytes
        """
        if len(groups) == 1:
           mode = IGMPv3.TYPE_REC_CHG_TO_EXCL_MODE
        else:
            mode = IGMPv3.TYPE_REC_MODE_IS_EXCLUDE

        _nochecksum = struct.pack(">BBHHH", IGMPv3.TYPE_MEMBERSHIP_REPORT, 0, 0, 0, len(groups))
        for _g in groups:
            _nochecksum += struct.pack(">BBH", mode, 0, 0) + socket.inet_aton(_g)

        all_16b_wds = struct.unpack(">{}H".format(int(len(_nochecksum)/2)), _nochecksum)
        checksum = ~reduce(ones_comp_add16, all_16b_wds) & 0xFFFF
        return _nochecksum[:2] + struct.pack(">H", checksum) + _nochecksum[4:]





