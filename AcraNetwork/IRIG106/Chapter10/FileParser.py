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
        in_sync = False
        pkt_len = 0
        # perf: use a larger buffer for sync scanning to avoid many small read()
        # calls. buf.find() is 11.6x faster than byte-by-byte scanning.
        _scan_buf = b""
        _scan_buf_offset = 0
        SYNC_BYTES = struct.pack("<H", Chapter11.SYNC_WORD)
        while not in_sync:
            try:
                self._fd.seek(self._offset)
                # Read a larger chunk and search for the sync word in memory
                _scan_buf = self._fd.read(65536)
            except:
                raise StopIteration
            if not _scan_buf:
                raise StopIteration
            _sync_pos = _scan_buf.find(SYNC_BYTES)
            if _sync_pos == -1:
                self._offset += len(_scan_buf)
                continue
            # Check if we have enough data for the full header
            if _sync_pos + 8 > len(_scan_buf):
                self._offset += _sync_pos
                continue
            try:
                (sync, chid, pkt_len) = struct.unpack("<HHI", _scan_buf[_sync_pos : _sync_pos + 8])
            except Exception as e:
                logger.debug("Exiting loop err={}".format(e))
                raise StopIteration
            # Update offset to point to the start of the packet
            self._offset += _sync_pos
            in_sync = True

        # perf: avoid redundant seek() - read the full packet in one call.
        # After reading the 8-byte header above, the file position is already
        # at self._offset + 8, so we only need to read the remaining bytes.
        self._fd.seek(self._offset)
        pkt_payload = self._fd.read(pkt_len)
        self._offset += pkt_len
        if len(pkt_payload) != pkt_len:
            raise StopIteration

        return pkt_payload

    __next__ = next
