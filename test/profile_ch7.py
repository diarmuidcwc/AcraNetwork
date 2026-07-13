import struct
import logging
import AcraNetwork.IRIG106.Chapter7 as ch7
from pstats import Stats
import cProfile
import typing
import base64


def get_pkts(max_len: int = 178, fill: bool = False) -> typing.Generator[tuple[bytes, ch7.PTDPDetails], None, None]:

    _fill = ch7.ptdp_fill(8).pack()
    count = 0
    while True:
        if fill:
            yield _fill, ch7.PTDPDetails(False, ch7.PTDPContent.FILL)
        else:
            # pkt_len = random.randint(2, 180)
            pkt_len = (count % max_len) + 2
            paylaod_int = [pkt_len] + [count] * (pkt_len - 1)
            payload = struct.pack(f">{pkt_len}Q", *paylaod_int)
            count += 1

            logging.debug(f"TX: Generated payload of length {pkt_len * 8} count={count}")
            yield payload, ch7.PTDPDetails(False, ch7.PTDPContent.ETHERNET_MAC)


def get_pcm_frame(offset_ptfr: int = 0, fill: bool = False, max_len: int = 178):
    pcm_frame_len = 1024
    ptfr_len = pcm_frame_len - offset_ptfr - 4
    zero_buf = struct.pack(">B", 0) * offset_ptfr
    for ptfr in ch7.datapkts_to_ptfr(get_pkts(max_len, fill), ptfr_len=ptfr_len):
        pcm_frame = zero_buf + ptfr.pack()
        logging.debug(f"TX pcm_frame_len={len(pcm_frame)} ptfr_len={ptfr_len}")
        yield pcm_frame


def get_frames() -> list:
    frames = []
    for _i, frame in enumerate(get_pcm_frame(0)):
        frames.append(frame)
        if _i == 1000:
            return frames
    return frames


def get_fill_frames() -> list:
    frames = []
    for _i, frame in enumerate(get_pcm_frame(0, fill=True)):
        frames.append(frame)
        if _i == 2000:
            return frames
    return frames


def full_profile(frames):
    _golay = ch7.Golay.Golay()
    pr = cProfile.Profile()
    pr.enable()
    offset = 0
    first_PTFR = True
    eth_p = bytes()
    remainder = None
    for frame in frames:
        ch7_pkt = ch7.PTFR(_golay)
        ch7_buffer = frame[offset:]
        ch7_pkt.length = len(ch7_buffer)
        ch7_pkt.unpack(ch7_buffer)

        for p, remainder, e in ch7_pkt.get_aligned_payload(first_PTFR, remainder):
            first_PTFR = False
            if p is not None:
                if p.length != 0:
                    if p.fragment == ch7.PTDPFragment.COMPLETE or p.fragment == ch7.PTDPFragment.LAST:
                        eth_p += p.payload
                        eth_p = bytes()
    ps = Stats(pr)
    ps.sort_stats("cumtime")
    ps.print_stats()


def full_profile_fill(frames):
    _golay = ch7.Golay.Golay()
    pr = cProfile.Profile()
    pr.enable()
    offset = 0
    first_PTFR = True
    fill_count = 0
    remainder = None
    for frame in frames:
        ch7_pkt = ch7.PTFR(_golay)
        ch7_buffer = frame[offset:]
        ch7_pkt.length = len(ch7_buffer)
        ch7_pkt.unpack(ch7_buffer)

        for p, remainder, e in ch7_pkt.get_aligned_payload(first_PTFR, remainder):
            first_PTFR = False
            if p is not None:
                if p.content != ch7.PTDPContent.FILL:
                    print("error")
                else:
                    fill_count += 1
    ps = Stats(pr)
    ps.sort_stats("cumtime")
    ps.print_stats()
    print(f"Fill count={fill_count}")


# full_profile_fill(get_fill_frames())
full_profile(get_frames())
# fill = ch7.ptdp_fill(8)
# print(fill.pack())
# print(base64.b64encode(fill.pack()).)
