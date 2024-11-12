import socket
import logging
import AcraNetwork.iNetX as inetx
import typing
import struct


PCM_HDR_LEN = 10


def string_matching_boyer_moore_horspool(text="", pattern=""):
    """
    Returns positions where pattern is found in text.
    O(n)
    Performance: ord() is slow so we shouldn't use it here
    Example: text = 'ababbababa', pattern = 'aba'
         string_matching_boyer_moore_horspool(text, pattern) returns [0, 5, 7]
    @param text text to search inside
    @param pattern string to search for
    @return list containing offsets (shifts) where pattern is found inside text
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
    def __init__(self, udp_port: int, timeout: float = 5.0, localaddress=""):

        self.recv_sockets = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sockets.settimeout(timeout)
        self.recv_sockets.bind((localaddress, udp_port))

        self._current_aligned = True
        self._payload_offset = 0
        self._sequence = None

        self.streamid = 0x153  #: StreamID on which to capture the SAM/DEC data
        self.frame_length = None  #: Calculate the frame length by searching the payload for the sync words
        # For the setup side. Most of the defaults are ok
        self.sync_word = 0xFE6B2840

        # Logging
        self._logger = logging.getLogger(__name__)

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
                raise Exception(e)
            else:
                yield data

    def frames(self) -> typing.Generator[bytes, None, None]:
        """Get the data from the underlying source, combine the IP fragments and then pull out the payload from the
        inetx packets and align them

        Raises:
            Exception: Cant unpacket the payload

        Yields:
            bytes: the payload captured
        """
        sync_packed = struct.pack(">I", self.sync_word)
        for udp_payload in self._get_data():
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
                            logging.warning(
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
