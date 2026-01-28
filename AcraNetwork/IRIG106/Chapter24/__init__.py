"""
.. module:: Chapter24
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct Chapter24 Packets

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

__author__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"


import struct
import enum
from dataclasses import dataclass, field


class EndOfDataFlag(enum.IntFlag):
    NORMAL = 0
    ENDOFDATAFLAG = 1


class DataSourceHealthFlag(enum.IntFlag):
    NOERROR = 0
    ERROR = 1


class DataSourceTimeLockFlag(enum.IntFlag):
    TIMELOCKED = 0
    TIMENOTLOCKED = 1


class DataSourceAcquiredDataFlag(enum.IntFlag):
    ACQUIRED = 0
    SIMULATED = 1


class MessageFragmentationFlags(enum.IntEnum):
    COMPLETE = 0
    FIRSTFRAGMENT = 1
    MIDDLEFRAGMENT = 2
    LASTFRAGMENT = 3


class PlaybackDataFlag(enum.IntFlag):
    LIVE = 0
    PLAYBACK = 1


class StandardPackageHeaderFlag(enum.IntEnum):
    NONSTD = 1
    STD = 0


FLAG_STRUCT = ">H"


@dataclass
class Flags:
    """
    Class to represent the flags in a TmNSMessage
    Use integers or the IntEnums above to populate this class

    """

    endofdata: EndOfDataFlag = EndOfDataFlag.NORMAL
    health: DataSourceHealthFlag = DataSourceHealthFlag.NOERROR
    timelock: DataSourceTimeLockFlag = DataSourceTimeLockFlag.TIMELOCKED
    acquired: DataSourceAcquiredDataFlag = DataSourceAcquiredDataFlag.ACQUIRED
    fragmentation: MessageFragmentationFlags = MessageFragmentationFlags.COMPLETE
    playback: PlaybackDataFlag = PlaybackDataFlag.LIVE
    std: StandardPackageHeaderFlag = StandardPackageHeaderFlag.STD

    def unpack(self, buffer: bytes):
        """
        Convert a 2 byte buffer into a flag object
        """
        (flag,) = struct.unpack(FLAG_STRUCT, buffer)
        self.endofdata = EndOfDataFlag(flag & 0x1)
        self.health = DataSourceHealthFlag((flag >> 1) & 0x1)
        self.timelock = DataSourceTimeLockFlag((flag >> 2) & 0x1)
        self.acquired = DataSourceAcquiredDataFlag((flag >> 3) & 0x1)
        self.fragmentation = MessageFragmentationFlags((flag >> 4) & 0x3)
        self.playback = PlaybackDataFlag((flag >> 6) & 0x1)
        self.std = StandardPackageHeaderFlag((flag >> 7) & 0x1)

    def pack(self) -> bytes:
        val = (
            self.endofdata.value
            + (self.health.value << 1)
            + (self.timelock.value << 2)
            + (self.acquired.value << 3)
            + (self.fragmentation.value << 4)
            + (self.playback.value << 6)
            + (self.std.value << 7)
        )
        return struct.pack(FLAG_STRUCT, val)


FLAG_NO_ERR = 0

TMNSPKT_FORMAT = ">IBBHI"


@dataclass
class TmNSPackage:
    packageid: int = 0
    length: int = 0
    flags: int = FLAG_NO_ERR
    timedelta: int = 0
    payload: bytes = bytes()

    def unpack(self, buffer: bytes):
        (self.packageid, self.flags, _res, self.length, self.timedelta) = struct.unpack_from(TMNSPKT_FORMAT, buffer)
        self.payload = buffer[12:]

    def pack(self) -> bytes:
        _hdr = struct.pack(TMNSPKT_FORMAT, self.packageid, self.flags, 0, self.length, self.timedelta)
        return _hdr + self.payload


class OptionKind(enum.IntEnum):
    """
    The Option kind fields defined for placement into a TmNSPackage
    """

    END = 0x0
    NOP = 0x1
    DATASOURCE_CONFIG = 0x82
    DATASOURCE_ERROR = 0x83
    DEST_ADDR = 0x85
    FRAGMENT_BYTE_OFFSET = 0x86
    PACKAGE_COUNT = 0x87
    INGRESS_TIMESTAMP = 0x88
    EGRESS_TIMESTAMP = 0x89


class ApplicationField:
    optionkind: int = OptionKind.END
    length: int = 2
    data: bytes = bytes()


TYPE_TMNS = 0
VERSION = 1


TMNS_STRUCT = ">BBIIIQ"


@dataclass
class TmNSMessage:
    """
    Class to represent an IRIG106 Chapter 24 TmNSMessage
    https://www.irig106.org/docs/106-17/chapter24.pdf

    Supports pack, which converts the object into bytes or unpack which takes a buffer and converts it into a TmNSMessage

    >>> import AcraNetwork.IRIG106.Chapter24 as ch24
    >>> import struct
    >>> pkt = ch24.TmNSMessage()
    >>> pkt.flags.acquired = ch24.DataSourceAcquiredDataFlag.SIMULATED
    >>> pkt.flags.fragmentation = ch24.MessageFragmentationFlags.LASTFRAGMENT
    >>> pkt.defintionid = 0x1234
    >>> pkt.sequence = 100
    >>> pkt.payload = struct.pack(">HH", 0x1, 0x2)
    >>> b = pkt.pack()

    """

    flags: Flags = field(default_factory=Flags)
    msgtype: int = TYPE_TMNS
    optionwordcount: int = 0
    version: int = VERSION
    defintionid: int = 0
    sequence: int = 0
    length: int = 0
    timestamp: int = 0
    appfields: list[OptionKind] = field(default_factory=list)
    payload: bytes = bytes()

    def unpack(self, buffer: bytes) -> None:
        """ "
        Convert the byte buffer into a TmNSMessage object
        """
        self.flags.unpack(buffer[0:2])
        (_type, _ver_opt, self.defintionid, self.sequence, self.length, self.timestamp) = struct.unpack_from(
            TMNS_STRUCT, buffer, 2
        )
        self.msgtype = _type & 0xF
        self.optionwordcount = _ver_opt & 0xF
        self.version = _ver_opt >> 4

        if self.optionwordcount > 0:
            # TODO
            _appfield = buffer[24 : (24 + self.optionwordcount * 4)]
        self.payload = buffer[(24 + self.optionwordcount * 4) :]

    def pack(self) -> bytes:
        """
        Returns the TmNSMessage as bytes for packing into a UDP packet
        """
        if len(self.payload) % 4 != 0:
            raise Exception("TmNS payuload needs to be 32b aligned")

        self.length = len(self)
        _hdr = self.flags.pack() + struct.pack(
            TMNS_STRUCT,
            self.msgtype,
            self.optionwordcount + (self.version << 4),
            self.defintionid,
            self.sequence,
            self.length,
            self.timestamp,
        )

        return _hdr + self.payload

    def __len__(self) -> int:
        return len(self.payload) + struct.calcsize(TMNS_STRUCT) + struct.calcsize(FLAG_STRUCT)
