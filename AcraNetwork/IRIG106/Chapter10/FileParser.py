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
        while not in_sync:
            try:
                self._fd.seek(self._offset)
                _first_few_words = self._fd.read(8)
            except:
                raise StopIteration
            try:
                (sync, chid, pkt_len) = struct.unpack("<HHI", _first_few_words)
            except Exception as e:
                logger.debug("Exiting loop err={}".format(e))
                raise StopIteration

            if sync == Chapter11.SYNC_WORD:
                in_sync = True
            else:
                self._offset += 1

        self._fd.seek(self._offset)
        pkt_payload = self._fd.read(pkt_len)
        self._offset += pkt_len
        if len(pkt_payload) != pkt_len:
            raise StopIteration

        return pkt_payload

    __next__ = next
