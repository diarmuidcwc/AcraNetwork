"""
Final benchmark: confirm which optimizations are worth implementing.

Only tests the optimizations that showed promise in the initial benchmarks.
"""
import struct
import timeit
import re
from AcraNetwork.IRIG106.Chapter7 import Golay, PTFR, PTDPContent, PTDPFragment

# Setup
golay = Golay.Golay()
fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
fill_len = len(fill_pattern)

# Create a PTFR with fill packets
ptfr = PTFR()
ptfr.length = 2000
ptfr.payload = fill_pattern * 200  # 200 fill packets
ptfr.ptdp_offset = 0

n = 2000

# ===================== OPTIMIZATION 1: self.payload caching =====================

def opt1_property():
    p = ptfr
    total = 0
    for _ in range(10):
        b = p.payload
        total += len(b)
    return total

def opt1_local():
    p = ptfr
    total = 0
    local_payload = p.payload
    for _ in range(10):
        b = local_payload
        total += len(b)
    return total

t1_prop = timeit.timeit(opt1_property, number=n)
t1_local = timeit.timeit(opt1_local, number=n)
print(f"Optimization 1 (self.payload):")
print(f"  Property access:  {t1_prop*1000:.3f} ms")
print(f"  Local variable:   {t1_local*1000:.3f} ms  ({t1_prop/t1_local:.2f}x)")

# ===================== OPTIMIZATION 2: PTDP attribute updates =====================

def opt2_all():
    p = PTFR()
    b = b"\x00" * 1000
    for i in range(100):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_buf = b
        p._ptdp._payload_off = i * 8 + 6
        p._ptdp._payload_cache = None
    return

def opt2_skip_cache():
    p = PTFR()
    b = b"\x00" * 1000
    for i in range(100):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_buf = b
        p._ptdp._payload_off = i * 8 + 6
        # _payload_cache skipped
    return

def opt2_minimal():
    p = PTFR()
    b = b"\x00" * 1000
    for i in range(100):
        p._ptdp.length = 2
        p._ptdp._payload_off = i * 8 + 6
    return

t2_all = timeit.timeit(opt2_all, number=n)
t2_skip = timeit.timeit(opt2_skip_cache, number=n)
t2_min = timeit.timeit(opt2_minimal, number=n)
print(f"\nOptimization 2 (PTDP updates x100):")
print(f"  All attributes:  {t2_all*1000:.3f} ms")
print(f"  Skip cache:      {t2_skip*1000:.3f} ms  ({t2_skip/t2_all:.2f}x)")
print(f"  Minimal:         {t2_min*1000:.3f} ms  ({t2_min/t2_all:.2f}x)")

# ===================== OPTIMIZATION 3: Buffer slicing =====================

run_re = re.compile(b"(?:" + re.escape(fill_pattern) + b")+")
buf = fill_pattern * 200

def opt3_slice():
    b = buf
    run_match = run_re.match(b)
    if run_match is not None:
        run_bytes = run_match.end()
        run_count = run_bytes // fill_len
        for _ in range(run_count):
            pass
        b = b[run_bytes:]
    for _ in range(200):
        pass
    return

def opt3_index():
    b = buf
    start = 0
    run_match = run_re.match(b, start)
    if run_match is not None:
        run_bytes = run_match.end()
        run_count = run_bytes // fill_len
        for _ in range(run_count):
            pass
        start = run_bytes
    for _ in range(200):
        pass
    return

n3 = 2000
t3_slice = timeit.timeit(opt3_slice, number=n3)
t3_index = timeit.timeit(opt3_index, number=n3)
print(f"\nOptimization 3 (buffer slicing, 200 fill pkts):")
print(f"  Slice:  {t3_slice*1000:.3f} ms")
print(f"  Index:  {t3_index*1000:.3f} ms  ({t3_index/t3_slice:.2f}x)")

# ===================== RECOMMENDATIONS =====================
print("\n" + "=" * 60)
print("FINAL RECOMMENDATIONS")
print("=" * 60)
if t1_prop > t1_local:
    print(f"1. Cache self.payload locally:    YES  ({t1_prop/t1_local:.2f}x speedup)")
else:
    print(f"1. Cache self.payload locally:    NO   ({t1_local/t1_prop:.2f}x slower)")

if t2_skip < t2_all:
    print(f"2. Skip _payload_cache = None:    YES  ({t2_all/t2_skip:.2f}x speedup)")
else:
    print(f"2. Skip _payload_cache = None:    NO   ({t2_skip/t2_all:.2f}x slower)")

if t2_min < t2_skip:
    print(f"3. Only update changed attrs:     YES  ({t2_skip/t2_min:.2f}x speedup)")
else:
    print(f"3. Only update changed attrs:     NO   ({t2_min/t2_skip:.2f}x slower)")

if t3_index < t3_slice:
    print(f"4. Index tracking (no slice):     YES  ({t3_slice/t3_index:.2f}x speedup)")
else:
    print(f"4. Index tracking (no slice):     NO   ({t3_index/t3_slice:.2f}x slower)")

print("5. Replace regex with byte cmp:    NO   (already tested, 3x slower)")
print("6. Replace regex with find():      NO   (already tested, 3x slower)")