import typing
from AcraNetwork.IRIG106.Chapter11 import Chapter11
import struct
import logging

logger = logging.getLogger(__name__)


class FileParser(object):
    """
    Parse a Chapter10 file. Open the file and iterate through it

    >>> fp = FileParser("_dummy.ch10", mode="wb")
    >>> with fp as ch10file:
    ... 	ch10file.write(bytes(10))

    """

    def __init__(self, filename, mode="rb"):
        self.filename = filename
        self._mode = mode
        self.insync = False
        self._offset = 0
        self._fd = None
        self._buf = b""
        self._buf_offset = 0

    def write(self, ch10packet: typing.Union[Chapter11, bytes]) -> None:
        """
        Write a chapter10 packet to the file

        :param ch10packet: The chapter 10 packet to write. Either bytes or Chapter10 object
        """
        if self._fd is None or self._mode != "wb":
            raise Exception("File name not defined")
        if not self._fd.writable():
            raise Exception("File {} not open for writing".format(self.filename))
        if isinstance(ch10packet, Chapter11):
            self._fd.write(ch10packet.pack())
        elif type(ch10packet) is bytes:
            self._fd.write(ch10packet)
        else:
            raise Exception("Write takes a ch10 packet or bytes")

    def __enter__(self):
        self._fd = open(self.filename, self._mode)
        return self

    def __exit__(self, type, value, traceback):
        # Exception handling here
        self._fd.close()

    def close(self):
        if self._fd is not None:
            self._fd.close()

    def __iter__(self):
        return self

    def next(self) -> bytes:
        SYNC_BYTES = struct.pack("<H", Chapter11.SYNC_WORD)

        while True:
            sync_pos = self._buf.find(SYNC_BYTES, self._buf_offset)

            if sync_pos == -1:
                self._offset += len(self._buf)
                self._buf = self._fd.read(65536)
                self._buf_offset = 0
                if not self._buf:
                    raise StopIteration
                continue

            if sync_pos + 8 > len(self._buf):
                self._offset += sync_pos
                self._buf = self._buf[sync_pos:]
                self._buf_offset = 0
                more = self._fd.read(65536)
                if not more:
                    raise StopIteration
                self._buf += more
                continue

            try:
                (sync, chid, pkt_len) = struct.unpack("<HHI", self._buf[sync_pos : sync_pos + 8])
            except Exception as e:
                logger.debug("Exiting loop err={}".format(e))
                raise StopIteration

            pkt_end = sync_pos + pkt_len
            if pkt_end > len(self._buf):
                needed = pkt_end - len(self._buf)
                more = self._fd.read(needed)
                if len(more) < needed:
                    raise StopIteration
                self._buf += more

            pkt_payload = self._buf[sync_pos:pkt_end]
            self._buf = self._buf[pkt_end:]
            self._buf_offset = 0
            self._offset += pkt_end
            return pkt_payload

    __next__ = next
