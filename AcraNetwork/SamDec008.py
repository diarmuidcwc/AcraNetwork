import socket
import logging
import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import typing
import struct


PCM_HDR_LEN = 10
logger = logging.getLogger(__name__)


def string_matching_boyer_moore_horspool(text: str = "", pattern: str = "") -> typing.List[int]:
    """
    Returns positions where pattern is found in text.
    O(n)
    Performance: ord() is slow so we shouldn't use it here
    Example: text = 'ababbababa', pattern = 'aba'
         string_matching_boyer_moore_horspool(text, pattern) returns [0, 5, 7]
    :param text: text to search inside
    :param pattern: string to search for
    :return: list containing offsets (shifts) where pattern is found inside text
    """
    m = len(pattern)
    n = len(text)
    offsets = []
    if m > n:
        return offsets
    skip = []
    for k in range(256):
        skip.append(m)
    for k in range(m - 1):
        my = pattern[k]
        skip[pattern[k]] = m - k - 1

    skip = tuple(skip)
    k = m - 1
    while k < n:
        j = m - 1
        i = k
        while j >= 0 and text[i] == pattern[j]:
            j -= 1
            i -= 1
        if j == -1:
            offsets.append(i + 1)
        k += skip[text[k]]

    return offsets


class SamDec008(object):
    """
    The SAM/DEC/008 is a USB power PCM decommutator (https://www.curtisswrightds.com/products/flight-test/ground-stations/samdec008)

    Once configured it will convert PCM frames into iNetX packets over UDP

    This class will capture UDP packets from the network, extract the iNetX payload and align the data to PCM frame
    boundaries. It will return PCM frames as bytes

    Supply the UDP port and the IP Address of the correct network interface card on your PC
    You can use ''  to let you OS decide

    :param udp_port: The receive UDP port number
    :type udp_port: int
    :param timeout: Timeout in seconds
    :type timeout: float
    :param localaddress: The local network interface ip address
    :type localaddress: str

    >>> samdec = SamDec008(8010, localaddress="127.0.0.1", timeout=0.5)
    >>> for frame in samdec.frames():
    ...     (syncword, sfid, word1) = struct.unpack_from(">IHH", frame)


    """

    def __init__(self, udp_port: int, timeout: float = 5.0, localaddress=""):

        self.recv_sockets = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sockets.settimeout(timeout)
        self.recv_sockets.bind((localaddress, udp_port))

        self._current_aligned = True
        self._payload_offset = 0
        self._sequence = None

        self.streamid = 0x153  #: StreamID on which to capture the SAM/DEC data. Default of 0x153 should be ok
        self.frame_length = None  #: This will be populated when seraching for frame sync words
        self.sync_word = 0xFE6B2840  #: The Frame sync word.

    def close(self):
        self.recv_sockets.close()

    def _get_data(self) -> typing.Generator[bytes, None, None]:
        """
        Get the data, agnostic to network vs pcap

        :rtype: collections.Iterable[str]
        """
        while True:
            try:
                data, addr = self.recv_sockets.recvfrom(10000)
            except Exception as e:
                yield None
            else:
                yield data

    def frames(self) -> typing.Generator[bytes, None, None]:
        """Get the data from the underlying source, combine the IP fragments and then pull out the payload from the
        inetx packets and align them

        Yields:
            bytes: the payload captured
        """
        sync_packed = struct.pack(">I", self.sync_word)
        for udp_payload in self._get_data():
            if udp_payload is None:
                return
            inetx_pkt = inetx.iNetX()
            try:
                inetx_pkt.unpack(udp_payload)
            except Exception as e:
                continue
            else:
                self._payload_offset = PCM_HDR_LEN  # The SAM DEC inserts some header
                if inetx_pkt.streamid == self.streamid:
                    if self._sequence is not None:
                        if self._sequence + 1 % pow(2, 64) == inetx_pkt.sequence:
                            logger.warning(
                                "Missing Sequence number at {}. Is SAM/DEC dropping?".format(inetx_pkt.sequence)
                            )
                    # Start with the previous segment and the current payload
                    payload = inetx_pkt.payload

                    if self.frame_length is None:
                        offset = string_matching_boyer_moore_horspool(payload, sync_packed)
                        if len(offset) == 0:
                            raise Exception("No Frame sync found")
                        elif len(offset) == 1:
                            self.frame_length = len(payload) - PCM_HDR_LEN
                        else:
                            self.frame_length = offset[1] - offset[0]

                    # If we get to within the last 4 bytes then hold it until the next segment
                    while (self._payload_offset + self.frame_length) <= len(payload):
                        # We have enough for a full frame
                        frame_buffer = payload[self._payload_offset : self._payload_offset + self.frame_length]
                        self._payload_offset += self.frame_length
                        # Verify that we are still in sync
                        if frame_buffer[:4] != sync_packed:
                            # Not in sync.
                            print("ERROR:Fell out of alignment at offset {}".format(self._payload_offset))
                            self.frame_length = None
                        else:
                            yield frame_buffer


class SamDecPcap(SamDec008):
    """
    The SAM/DEC/008 is a USB power PCM decommutator (https://www.curtisswrightds.com/products/flight-test/ground-stations/samdec008)

    Once configured it will convert PCM frames into iNetX packets over UDP

    This class will take iNetx packet fromn a pcap file, extract the iNetX payload and align the data to PCM frame
    boundaries. It will return PCM frames as bytes

    :param pcap_fname: The PCAP filename
    :type pcap_fname: str


    >>> samdec = SamDecPcap("test/sample_pcap/samdec.pcap")
    >>> for frame in samdec.frames():
    ...     (syncword, sfid, word1) = struct.unpack_from(">IHH", frame)
    ...     print(f"SW={syncword:#0X} sfid={sfid}")
    SW=0XFE6B2840 sfid=4
    SW=0XFE6B2840 sfid=5
    SW=0XFE6B2840 sfid=6
    SW=0XFE6B2840 sfid=7

    """

    def __init__(self, pcap_fname: str):

        self._pcap = pcap.Pcap(pcap_fname, mode="r")

        self._current_aligned = True
        self._payload_offset = 0
        self._sequence = None

        self.streamid = 0x153  #: StreamID on which to capture the SAM/DEC data. Default of 0x153 should be ok
        self.frame_length = None  #: This will be populated when seraching for frame sync words
        self.sync_word = 0xFE6B2840  #: The Frame sync word.

    def close(self):
        self._pcap.close()

    def _get_data(self) -> typing.Generator[bytes, None, None]:
        """
        Get the data, agnostic to network vs pcap

        :rtype: collections.Iterable[str]
        """
        UDP_TYPE = 17
        for rec in self._pcap:
            if len(rec.payload) > 0x46:
                (ip_type,) = struct.unpack_from(">B", rec.payload, 0x17)
                if ip_type == UDP_TYPE:
                    data = rec.payload[0x2A:]
                    logger.debug(f"FrameLen={len(data)}")
                    yield data
