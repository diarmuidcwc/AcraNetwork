import typing
import struct
from MPEGTS import MPEGPacket


def bytes_to_ascii(buffer: bytes) -> str:
    r = ""
    for _b in buffer:
        r += chr(_b)
    return r


class DescriptorTag(object):
    def __init__(self) -> None:
        self.tag: int = None
        self.data: bytes = bytes()

    def unpack(self, buffer: bytes) -> bytes:
        """Unpack the buffer into a descriptor and return any remainder

        Args:
            buffer (bytes): _description_

        Returns:
            : _description_
        """
        (self.tag, _len) = struct.unpack_from(">BB", buffer)
        self.data = buffer[2 : 2 + _len]
        return buffer[_len:]

    def pack(self) -> bytes:
        return struct.pack(">BB", self.tag, len(self.data)) + self.data

    def __len__(self) -> int:
        if self.tag is None:
            return 0
        return 2 + len(self.data)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DescriptorTag):
            return False
        if self.tag != value.tag or self.data != value.data:
            return False
        return True

    def __repr__(self) -> str:
        return f"Tag={self.tag:#0X} Format={bytes_to_ascii(self.data)}"


MIN_STREAM_LEN = 5


class PMTStream(object):
    def __init__(self) -> None:
        self.streamtype: int = 0x0
        self.elementary_pid: int = 0
        self.descriptor_tags: typing.List[DescriptorTag] = []

    def unpack(self, buffer: bytes):
        (self.streamtype, _pid, _len) = struct.unpack_from(">BHH", buffer)
        self.elementary_pid = _pid & 0x1FFF
        es_len = _len & 0xFFF
        es_buffer = buffer[MIN_STREAM_LEN:]
        while len(es_buffer) >= MIN_STREAM_LEN:
            tag = DescriptorTag()
            es_buffer = tag.unpack(es_buffer)
            self.descriptor_tags.append(tag)

    def pack(self) -> bytes:
        _payload = bytes()
        for tag in self.descriptor_tags:
            _payload += tag.pack()
        hdr = struct.pack(">BHH", self.streamtype, self.elementary_pid + 0xE000, len(_payload) + 0xF000)
        return hdr + _payload

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, PMTStream):
            return False
        if (
            self.streamtype != value.streamtype
            or self.elementary_pid != value.elementary_pid
            or self.descriptor_tags != value.descriptor_tags
        ):
            return False
        return True


class MPEGPacketPMT(MPEGPacket):
    def unpack(self, buf: bytes):
        return super().unpack(buf)

    def pack(self) -> bytes:
        return super().pack()
