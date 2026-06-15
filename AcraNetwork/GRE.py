import typing
import struct

GRE_MAX_SEQ = pow(2, 32)
GRE_TYPE_SECURE_DATA = 0x876D
GRE_TYPE_RESERVED = 0xFFFF


class GRE(object):
    """
    Generic Routing Encapsulation (GRE) defined in RFC1701
    This implements a single variant of this only.
    Sequence number supported and no other optional fiend
    """

    def __init__(self) -> None:
        self.protocol_type: int = GRE_TYPE_RESERVED
        self.sequence: int = 0
        self.payload: typing.Optional[bytes] = None

    def pack(self) -> bytes:
        flags = 1 << 12
        _hdr = struct.pack(">HHI", flags, self.protocol_type, self.sequence % GRE_MAX_SEQ)
        return _hdr + self.payload
