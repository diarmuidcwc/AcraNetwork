"""
Precise benchmarks for actual get_aligned_payload patterns.

These benchmarks test the actual code patterns used in get_aligned_payload,
not simplified versions. Only optimizations that show clear improvement
will be implemented.
"""

import struct
import timeit
import re
from AcraNetwork.IRIG106.Chapter7 import Golay, PTDP, PTFR, PTDPContent, PTDPFragment

# =============================================================================
# SECTION 1: Accurate fill packet processing benchmark
# =============================================================================

def benchmark_fill_packet_pattern():
    """
    Test the exact pattern used in get_aligned_payload for fill packet detection.

    The code does:
      run_match = self._fill_run_re.match(buf)
      if run_match is not None:
          run_bytes = run_match.end()
          run_count = run_bytes // fill_len_total
          for _fill_i in range(run_count):
              ... update PTDP ...
              yield ...
          buf = buf[run_bytes:]  # slice once after full run
          continue

    The optimization suggestion is to avoid the single slice after the
    run by tracking an index. This also tests using re.match() with
    a pos argument instead of re-slicing.
    """
    print("=" * 70)
    print("SECTION 1: Fill packet processing (exact code pattern)")
    print("=" * 70)

    # Setup
    golay = Golay.Golay()
    fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
    fill_len = len(fill_pattern)
    run_re = re.compile(b"(?:" + re.escape(fill_pattern) + b")+")

    # Create a buffer with 20 fill packets (realistic), then 20 non-fill
    buf = fill_pattern * 20 + b"\x01" * 200

    # Approach A: Current code (match + slice once)
    def current():
        b = buf
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            run_count = run_bytes // fill_len
            # Process fill packets
            for _fill_i in range(run_count):
                pass  # PTDP updates omitted - that's a separate benchmark
            # Slice once
            b = b[run_bytes:]
        # Process non-fill
        while b:
            b = b[10:]  # simulate normal packet processing
        return b

    # Approach B: Index tracking (no slice)
    def index_tracked():
        b = buf
        start = 0
        run_match = run_re.match(b)
        if run_match is not None:
            run_bytes = run_match.end()
            run_count = run_bytes // fill_len
            # Process fill packets
            for _fill_i in range(run_count):
                pass
            # Just advance index, no slice
            start = run_bytes
        # Process non-fill
        while start < len(b):
            start += 10  # simulate normal packet processing
        return b[:start] if start else b

    n = 20000

    t_current = timeit.timeit(current, number=n)
    t_index = timeit.timeit(index_tracked, number=n)

    print(f"\nTest: 20 fill + 20 normal packets ({n} iterations)")
    print(f"  Current (slice once):  {t_current*1000:.3f} ms  (baseline)")
    print(f"  Index tracking:        {t_index*1000:.3f} ms  ({t_index/t_current:.2f}x)")
    print(f"  Speedup:               {((t_current - t_index) / t_current * 100):.1f}%")

    # Test with many fill runs (1000 packets, each run is 1 fill, 1 normal)
    buf2 = b""
    for _ in range(1000):
        buf2 += fill_pattern + b"\x01" * 20

    def current_many():
        b = buf2
        total = 0
        while b:
            run_match = run_re.match(b)
            if run_match is not None:
                run_bytes = run_match.end()
                run_count = run_bytes // fill_len
                for _fill_i in range(run_count):
                    total += 1
                b = b[run_bytes:]
            # Process one normal packet (20 bytes)
            if b:
                b = b[20:] if len(b) >= 20 else b""
        return total

    def index_many():
        b = buf2
        start = 0
        total = 0
        while start < len(b):
            run_match = run_re.match(b, start)
            if run_match is not None:
                run_bytes = run_match.end()
                run_count = run_bytes // fill_len
                for _fill_i in range(run_count):
                    total += 1
                start = run_bytes
            # Process one normal packet (20 bytes)
            if start < len(b):
                start += 20
        return total

    n2 = 2000
    t_current_many = timeit.timeit(current_many, number=n2)
    t_index_many = timeit.timeit(index_many, number=n2)

    print(f"\nTest: 1000 fill + 1000 normal packets ({n2} iterations)")
    print(f"  Current (slice once):  {t_current_many*1000:.3f} ms  (baseline)")
    print(f"  Index tracking:        {t_index_many*1000:.3f} ms  ({t_index_many/t_current_many:.2f}x)")
    print(f"  Speedup:               {((t_current_many - t_index_many) / t_current_many * 100):.1f}%")

    return {"current": t_current, "index": t_index, "current_many": t_current_many, "index_many": t_index_many}


# =============================================================================
# SECTION 2: Mixed optimizations - combined effect
# =============================================================================

def benchmark_combined_optimizations():
    """
    Test the combined effect of:
    1. Local payload caching
    2. Simplified PTDP updates on fill packets
    3. Index tracking (avoiding buffer slicing)

    This simulates a realistic get_aligned_payload scenario.
    """
    print("\n" + "=" * 70)
    print("SECTION 2: Combined optimizations")
    print("=" * 70)

    # Create a PTFR with fill packets in the payload
    golay = Golay.Golay()
    fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
    fill_len = len(fill_pattern)

    # Create PTFR
    ptfr = PTFR()
    ptfr.length = 2000
    ptfr.payload = fill_pattern * 200  # 200 fill packets
    ptfr.ptdp_offset = 0

    # Create a test PTDP for unpacking
    ptdp = PTDP()
    ptdp.content = PTDPContent.FILL
    ptdp.length = 2
    ptdp.payload = bytearray(b"\xff\xff")

    # This benchmark won't test the full pipeline (Golay decode, etc.)
    # but will test the overhead of the Python-level operations

    n = 2000

    # Approach: Current code pattern
    def current_combined():
        # Simulate the current approach
        p = ptfr
        buf = p.payload
        run_re = p._fill_run_re
        fill_len2 = p._fill_len2_total
        count = 0

        while buf:
            run_match = run_re.match(buf)
            if run_match is not None:
                run_bytes = run_match.end()
                run_count = run_bytes // fill_len2
                for _fill_i in range(run_count):
                    # Current PTDP updates
                    p._ptdp.length = 2
                    p._ptdp.fragment = PTDPFragment.COMPLETE
                    p._ptdp.content = PTDPContent.FILL
                    p._ptdp.low_latency = False
                    p._ptdp._payload_buf = buf
                    p._ptdp._payload_off = _fill_i * fill_len2 + 6
                    p._ptdp._payload_cache = None
                    count += 1
                buf = buf[run_bytes:]
            else:
                break
        return count

    # Approach: Optimized code pattern
    def optimized_combined():
        p = ptfr
        local_payload = p.payload
        run_re = p._fill_run_re
        fill_len2 = p._fill_len2_total
        count = 0
        buf = local_payload
        buf_start = 0

        while buf_start < len(buf):
            run_match = run_re.match(buf, buf_start)
            if run_match is not None:
                run_bytes = run_match.end()
                run_count = run_bytes // fill_len2
                for _fill_i in range(run_count):
                    fill_offset = _fill_i * fill_len2
                    # Only update changed attributes
                    p._ptdp.length = 2
                    p._ptdp._payload_off = fill_offset + 6
                    p._ptdp._payload_buf = buf
                    # fragment, content, low_latency unchanged (already set from previous iteration)
                    # _payload_cache = None is unnecessary
                    count += 1
                buf_start = run_bytes
            else:
                break
        return count

    t_current = timeit.timeit(current_combined, number=n)
    t_optimized = timeit.timeit(optimized_combined, number=n)

    print(f"\nTest: 200 fill packets ({n} iterations)")
    print(f"  Current:    {t_current*1000:.3f} ms  (baseline)")
    print(f"  Optimized:  {t_optimized*1000:.3f} ms  ({t_optimized/t_current:.2f}x)")
    print(f"  Speedup:    {((t_current - t_optimized) / t_current * 100):.1f}%")

    return {"current": t_current, "optimized": t_optimized}


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("Precise Optimization Benchmarks for get_aligned_payload")
    print("=" * 70)
    print()

    r1 = benchmark_fill_packet_pattern()
    r2 = benchmark_combined_optimizations()

    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)
    print()

    # Section 1 analysis
    if r1["index"] < r1["current"]:
        print("1. Index tracking:   IMPLEMENT - {:.1f}% faster".format(
            (1 - r1["index"]/r1["current"]) * 100))
    else:
        print("1. Index tracking:   SKIP - {:.1f}% slower".format(
            (r1["index"]/r1["current"] - 1) * 100))

    if r1["index_many"] < r1["current_many"]:
        print("   (many runs):      IMPLEMENT - {:.1f}% faster".format(
            (1 - r1["index_many"]/r1["current_many"]) * 100))
    else:
        print("   (many runs):      SKIP - {:.1f}% slower".format(
            (r1["index_many"]/r1["current_many"] - 1) * 100))

    # Section 2 analysis
    if r2["optimized"] < r2["current"]:
        print("2. Combined:        IMPLEMENT - {:.1f}% faster".format(
            (1 - r2["optimized"]/r2["current"]) * 100))
    else:
        print("2. Combined:        SKIP - {:.1f}% slower".format(
            (r2["optimized"]/r2["current"] - 1) * 100))

    print()
    print("Combined speedup estimate: {:.1f}x".format(r2["current"] / r2["optimized"]))
    print("=" * 70)


if __name__ == "__main__":
    main()