"""
Benchmark individual optimizations for get_aligned_payload.

Each optimization is tested in isolation using timeit to determine
whether it actually improves performance before implementing it.
"""

import struct
import timeit
import re
from AcraNetwork.IRIG106.Chapter7 import Golay, PTDP, PTFR, PTDPContent, PTDPFragment

# =============================================================================
# SECTION 1: Buffer slicing vs index tracking
# =============================================================================

def benchmark_buffer_slicing():
    """
    Benchmark: buf = buf[run_bytes:]  vs  tracking buf_start index.

    In the fill packet run, the code slices the buffer to advance past
    processed fill packets. Tracking an index avoids re-allocating a new
    bytes object for each fill packet.
    """
    print("=" * 70)
    print("OPTIMIZATION 1: Buffer slicing vs index tracking")
    print("=" * 70)

    # Create a buffer with fill packets
    golay = Golay.Golay()
    fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
    buf = fill_pattern * 2000  # 2000 fill packets = 16000 bytes

    fill_len_total = len(fill_pattern)

    # Approach A: Current approach (buffer slicing)
    def approach_slicing():
        b = buf
        # Simulate processing 2000 fill packets one at a time
        start = 0
        while start < len(b):
            # Check if it's a fill pattern
            if b[start:start+fill_len_total] == fill_pattern:
                # Consume buffer by slicing
                b = b[start + fill_len_total:]
                start = 0
            else:
                break

    # Approach B: Index tracking (no slicing)
    def approach_index():
        b = buf
        start = 0
        while start < len(b):
            # Check if it's a fill pattern
            if b[start:start+fill_len_total] == fill_pattern:
                # Advance index, no slicing
                start += fill_len_total
            else:
                break

    # Approach C: Regex match (current approach in get_aligned_payload)
    run_re = re.compile(b"(?:" + re.escape(fill_pattern) + b")+")

    def approach_regex():
        b = buf
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            # Consume buffer by slicing
            b = b[run_bytes:]

    # Approach D: Regex match + index tracking
    def approach_regex_index():
        b = buf
        start = 0
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            # Advance index, no slicing
            start += run_bytes

    # Also test with a single fill packet to see overhead per packet
    single_buf = fill_pattern * 1

    def approach_slicing_single():
        b = single_buf
        start = 0
        if b[start:start+fill_len_total] == fill_pattern:
            b = b[start + fill_len_total:]

    def approach_index_single():
        b = single_buf
        start = 0
        if b[start:start+fill_len_total] == fill_pattern:
            start += fill_len_total

    def approach_regex_single():
        b = single_buf
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            b = b[run_bytes:]

    def approach_regex_index_single():
        b = single_buf
        start = 0
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            start += run_bytes

    n = 5000

    print(f"\nTest: 2000 consecutive fill packets ({n} iterations)")
    t_slicing = timeit.timeit(approach_slicing, number=n)
    t_index = timeit.timeit(approach_index, number=n)
    t_regex = timeit.timeit(approach_regex, number=n)
    t_regex_index = timeit.timeit(approach_regex_index, number=n)

    print(f"  Slicing (+slice):    {t_slicing*1000:.3f} ms  ({t_slicing/t_index:.2f}x)")
    print(f"  Index (no slice):    {t_index*1000:.3f} ms  (baseline)")
    print(f"  Regex+slicing:       {t_regex*1000:.3f} ms  ({t_regex/t_index:.2f}x)")
    print(f"  Regex+index:         {t_regex_index*1000:.3f} ms  ({t_regex_index/t_index:.2f}x)")

    print(f"\nTest: 1 fill packet ({n} iterations)")
    t_slicing_s = timeit.timeit(approach_slicing_single, number=n)
    t_index_s = timeit.timeit(approach_index_single, number=n)
    t_regex_s = timeit.timeit(approach_regex_single, number=n)
    t_regex_index_s = timeit.timeit(approach_regex_index_single, number=n)

    print(f"  Slicing (+slice):    {t_slicing_s*1000:.3f} ms  ({t_slicing_s/t_index_s:.2f}x)")
    print(f"  Index (no slice):    {t_index_s*1000:.3f} ms  (baseline)")
    print(f"  Regex+slicing:       {t_regex_s*1000:.3f} ms  ({t_regex_s/t_index_s:.2f}x)")
    print(f"  Regex+index:         {t_regex_index_s*1000:.3f} ms  ({t_regex_index_s/t_index_s:.2f}x)")

    return {
        "slicing": t_slicing,
        "index": t_index,
        "regex": t_regex,
        "regex_index": t_regex_index,
        "slicing_s": t_slicing_s,
        "index_s": t_index_s,
        "regex_s": t_regex_s,
        "regex_index_s": t_regex_index_s,
    }


# =============================================================================
# SECTION 2: self.payload property access
# =============================================================================

def benchmark_payload_property():
    """
    Benchmark: self.payload vs local_payload = self.payload.

    The property getter is called multiple times in get_aligned_payload.
    Caching it locally avoids the property call overhead.
    """
    print("\n" + "=" * 70)
    print("OPTIMIZATION 2: self.payload property access")
    print("=" * 70)

    # Create a PTFR with a payload
    ptfr = PTFR()
    ptfr.length = 1000
    ptfr.payload = b"\x00" * 900  # 900 bytes of payload

    n = 100000

    # Approach A: Access via property each time
    def approach_property():
        for _ in range(100):
            _ = ptfr.payload

    # Approach B: Cache locally
    def approach_local():
        local_payload = ptfr.payload
        for _ in range(100):
            _ = local_payload

    t_property = timeit.timeit(approach_property, number=n)
    t_local = timeit.timeit(approach_local, number=n)

    print(f"\nTest: 100 accesses per iteration ({n} iterations)")
    print(f"  Property access:  {t_property*1000:.3f} ms  ({t_property/t_local:.2f}x)")
    print(f"  Local variable:   {t_local*1000:.3f} ms  (baseline)")
    print(f"  Speedup:          {t_property/t_local:.2f}x")

    # Also test for PTDP lazy payload property
    ptfr2 = PTFR()
    ptfr2.length = 1000
    payload = b"\x00" * 900
    ptfr2.payload = payload  # This sets _payload

    # Simulate the current code path (multiple accesses)
    def approach_mixed():
        b1 = ptfr2.payload
        b2 = ptfr2.payload
        b3 = ptfr2.payload
        return b1, b2, b3

    def approach_mixed_local():
        p = ptfr2.payload
        b1 = p
        b2 = p
        b3 = p
        return b1, b2, b3

    t_mixed = timeit.timeit(approach_mixed, number=n)
    t_mixed_local = timeit.timeit(approach_mixed_local, number=n)

    print(f"\nTest: 3 payload accesses per iteration ({n} iterations)")
    print(f"  Property access:  {t_mixed*1000:.3f} ms  ({t_mixed/t_mixed_local:.2f}x)")
    print(f"  Local variable:   {t_mixed_local*1000:.3f} ms  (baseline)")

    return {
        "property": t_property,
        "local": t_local,
        "mixed": t_mixed,
        "mixed_local": t_mixed_local,
    }


# =============================================================================
# SECTION 3: PTDP attribute updates for fill packets
# =============================================================================

def benchmark_ptdp_updates():
    """
    Benchmark: Updating all PTDP attributes vs only changed ones.

    For fill packets, the code updates self._ptdp.length, .fragment, .content,
    .low_latency, ._payload_buf, ._payload_off, ._payload_cache.
    Some of these may be unnecessary.
    """
    print("\n" + "=" * 70)
    print("OPTIMIZATION 3: PTDP attribute updates for fill packets")
    print("=" * 70)

    n = 50000

    # Approach A: Update all attributes (current approach)
    def approach_all():
        ptfr = PTFR()
        for i in range(100):
            ptfr._ptdp.length = 2
            ptfr._ptdp.fragment = PTDPFragment.COMPLETE
            ptfr._ptdp.content = PTDPContent.FILL
            ptfr._ptdp.low_latency = False
            ptfr._ptdp._payload_buf = b"\x00" * 8
            ptfr._ptdp._payload_off = 6
            ptfr._ptdp._payload_cache = None

    # Approach B: Skip _payload_cache = None (already None if first time)
    def approach_skip_cache():
        ptfr = PTFR()
        for i in range(100):
            ptfr._ptdp.length = 2
            ptfr._ptdp.fragment = PTDPFragment.COMPLETE
            ptfr._ptdp.content = PTDPContent.FILL
            ptfr._ptdp.low_latency = False
            ptfr._ptdp._payload_buf = b"\x00" * 8
            ptfr._ptdp._payload_off = 6

    # Approach C: Only update length and offset (minimal)
    def approach_minimal():
        ptfr = PTFR()
        for i in range(100):
            ptfr._ptdp.length = 2
            ptfr._ptdp._payload_off = 6

    t_all = timeit.timeit(approach_all, number=n)
    t_skip_cache = timeit.timeit(approach_skip_cache, number=n)
    t_minimal = timeit.timeit(approach_minimal, number=n)

    print(f"\nTest: 100 PTDP updates per iteration ({n} iterations)")
    print(f"  All attributes:           {t_all*1000:.3f} ms  (baseline)")
    print(f"  Skip _payload_cache:      {t_skip_cache*1000:.3f} ms  ({t_skip_cache/t_all:.2f}x)")
    print(f"  Minimal (len+offset):     {t_minimal*1000:.3f} ms  ({t_minimal/t_all:.2f}x)")

    # Per-packet cost
    per_packet_all = t_all / n / 100 * 1e9
    per_packet_skip = t_skip_cache / n / 100 * 1e9
    per_packet_min = t_minimal / n / 100 * 1e9

    print(f"\n  Per-packet cost:")
    print(f"    All attributes:    {per_packet_all:.1f} ns")
    print(f"    Skip cache:        {per_packet_skip:.1f} ns (saves {per_packet_all - per_packet_skip:.1f} ns)")
    print(f"    Minimal:           {per_packet_min:.1f} ns (saves {per_packet_all - per_packet_min:.1f} ns)")

    return {
        "all": t_all,
        "skip_cache": t_skip_cache,
        "minimal": t_minimal,
    }


# =============================================================================
# SECTION 4: Regex match on full buffer vs on sliced buffer
# =============================================================================

def benchmark_regex_on_buffer():
    """
    Benchmark: Regex match on the full buffer vs on a slice.

    In the current code, the regex match is called on 'buf' which is
    the full remaining buffer. After each fill run, 'buf' is sliced.
    With index tracking, we could avoid the slice and just pass the
    original buffer with an offset.
    """
    print("\n" + "=" * 70)
    print("OPTIMIZATION 4: Regex match on full vs sliced buffer")
    print("=" * 70)

    # Create a buffer with fill packets
    golay = Golay.Golay()
    fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
    buf = fill_pattern * 2000
    run_re = re.compile(b"(?:" + re.escape(fill_pattern) + b")+")

    n = 5000

    # Approach A: Match on full buffer, then slice
    def approach_match_slice():
        b = buf
        for _ in range(2000):
            m = run_re.match(b)
            if m:
                run_bytes = m.end()
                # Check if we've consumed all fill packets
                b = b[run_bytes:]  # slice
            else:
                break

    # Approach B: Track index, no slicing
    def approach_match_index():
        b = buf
        start = 0
        for _ in range(2000):
            # Match on the relevant portion
            m = run_re.match(b, start)
            if m:
                run_bytes = m.end()
                start = run_bytes  # just advance index
            else:
                break

    t_slice = timeit.timeit(approach_match_slice, number=n)
    t_index = timeit.timeit(approach_match_index, number=n)

    print(f"\nTest: 2000 fill packets, match each ({n} iterations)")
    print(f"  Match+slice:  {t_slice*1000:.3f} ms  ({t_slice/t_index:.2f}x)")
    print(f"  Match+index:  {t_index*1000:.3f} ms  (baseline)")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("Individual Optimization Benchmarks for get_aligned_payload")
    print("=" * 70)
    print("\nEach optimization is tested in isolation. Only optimizations that")
    print("show significant improvement will be implemented.")
    print()

    results = {}

    r1 = benchmark_buffer_slicing()
    results["slicing"] = r1

    r2 = benchmark_payload_property()
    results["payload"] = r2

    r3 = benchmark_ptdp_updates()
    results["ptdp_updates"] = r3

    benchmark_regex_on_buffer()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print("Optimization 1 (Buffer slicing):")
    slic = results["slicing"]
    print(f"  2000 packets: Index={slic['index']*1000:.3f}ms, Slicing={slic['slicing']*1000:.3f}ms ({slic['slicing']/slic['index']:.2f}x)")
    print(f"  1 packet:     Index={slic['index_s']*1000:.3f}ms, Slicing={slic['slicing_s']*1000:.3f}ms ({slic['slicing_s']/slic['index_s']:.2f}x)")
    if slic['slicing'] > slic['index']:
        print("  >>> RECOMMEND: Use index tracking instead of slicing")
    else:
        print("  >>> Slicing is faster, keep current approach")

    print()
    print("Optimization 2 (Payload property):")
    pay = results["payload"]
    print(f"  Property: {pay['property']*1000:.3f}ms, Local: {pay['local']*1000:.3f}ms ({pay['property']/pay['local']:.2f}x)")
    if pay['property'] > pay['local']:
        print("  >>> RECOMMEND: Cache payload in local variable")
    else:
        print("  >>> Property access is faster, keep current approach")

    print()
    print("Optimization 3 (PTDP updates):")
    ptdp = results["ptdp_updates"]
    print(f"  All: {ptdp['all']*1000:.3f}ms, Skip cache: {ptdp['skip_cache']*1000:.3f}ms, Minimal: {ptdp['minimal']*1000:.3f}ms")
    if ptdp['skip_cache'] < ptdp['all']:
        print("  >>> RECOMMEND: Skip unnecessary _payload_cache = None")
    if ptdp['minimal'] < ptdp['skip_cache']:
        print("  >>> RECOMMEND: Only update changed attributes")
    else:
        print("  >>> Keep current approach")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()