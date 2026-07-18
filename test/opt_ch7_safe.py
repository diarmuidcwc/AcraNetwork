"""
Benchmark safe optimizations for get_aligned_payload fill packet loop.

Tests each optimization individually, then as a combined patch.
Only safe optimizations are tested (no correctness violations).
"""

import struct
import timeit
import re
from AcraNetwork.IRIG106.Chapter7 import Golay, PTFR, PTDPContent, PTDPFragment

# Setup
golay = Golay.Golay()
fill_pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", 0xAAAA)
fill_len = len(fill_pattern)
run_re = re.compile(b"(?:" + re.escape(fill_pattern) + b")+")
buf = fill_pattern * 200
run_match = run_re.match(buf)
run_bytes = run_match.end()
run_count = run_bytes // fill_len
fill_len_total = fill_len

n = 5000

# ===================== SAFE BASELINE =====================
# This is the current code exactly as written
def safe_baseline():
    p = PTFR()
    b = buf
    count = 0
    for _fill_i in range(run_count):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_buf = b
        p._ptdp._payload_off = _fill_i * fill_len_total + 6
        p._ptdp._payload_cache = None
        count += 1
    return count

t_baseline = timeit.timeit(safe_baseline, number=n)
print(f"Baseline (current):       {t_baseline*1000:.3f} ms")

# ===================== OPT A: Hoist _payload_buf =====================
def opt_hoist_buf():
    p = PTFR()
    b = buf
    p._ptdp._payload_buf = b  # hoisted out of loop
    count = 0
    for _fill_i in range(run_count):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_off = _fill_i * fill_len_total + 6
        p._ptdp._payload_cache = None
        count += 1
    return count

t_opt_a = timeit.timeit(opt_hoist_buf, number=n)
print(f"Opt A (hoist buf):        {t_opt_a*1000:.3f} ms  ({t_opt_a/t_baseline:.2f}x)")

# ===================== OPT B: Addition instead of multiply =====================
def opt_add():
    p = PTFR()
    b = buf
    p._ptdp._payload_buf = b
    p._ptdp._payload_off = 6  # first packet offset
    count = 0
    for _fill_i in range(run_count):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_cache = None
        count += 1
        p._ptdp._payload_off += fill_len_total  # add for next packet
    return count

t_opt_b = timeit.timeit(opt_add, number=n)
print(f"Opt B (add offset):      {t_opt_b*1000:.3f} ms  ({t_opt_b/t_baseline:.2f}x)")

# ===================== OPT C: hoist buf + add offset =====================
def opt_combined():
    p = PTFR()
    b = buf
    p._ptdp._payload_buf = b
    p._ptdp._payload_off = 6
    count = 0
    for _fill_i in range(run_count):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        p._ptdp._payload_cache = None
        count += 1
        p._ptdp._payload_off += fill_len_total
    return count

t_opt_c = timeit.timeit(opt_combined, number=n)
print(f"Opt C (combined):         {t_opt_c*1000:.3f} ms  ({t_opt_c/t_baseline:.2f}x)")

# ===================== OPT D: Combined + cache _ptdp =====================
def opt_cached():
    p = PTFR()
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    _ptdp._payload_off = 6
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp.fragment = PTDPFragment.COMPLETE
        _ptdp.content = PTDPContent.FILL
        _ptdp.low_latency = False
        _ptdp._payload_cache = None
        count += 1
        _ptdp._payload_off += fill_len_total
    return count

t_opt_d = timeit.timeit(opt_cached, number=n)
print(f"Opt D (cached+combined):  {t_opt_d*1000:.3f} ms  ({t_opt_d/t_baseline:.2f}x)")

# ===================== OPT E: Minimal safe =====================
# Only skip _payload_cache = None (which we know is safe from earlier testing)
# and hoist _payload_buf
def opt_minimal():
    p = PTFR()
    b = buf
    p._ptdp._payload_buf = b
    p._ptdp._payload_off = 6
    count = 0
    for _fill_i in range(run_count):
        p._ptdp.length = 2
        p._ptdp.fragment = PTDPFragment.COMPLETE
        p._ptdp.content = PTDPContent.FILL
        p._ptdp.low_latency = False
        # _payload_cache = None is still needed for correctness
        p._ptdp._payload_cache = None
        count += 1
        p._ptdp._payload_off += fill_len_total
    return count

t_opt_e = timeit.timeit(opt_minimal, number=n)
print(f"Opt E (minimal safe):     {t_opt_e*1000:.3f} ms  ({t_opt_e/t_baseline:.2f}x)")

# ===================== SUMMARY =====================
print("\n" + "=" * 60)
print("SAFE OPTIMIZATIONS")
print("=" * 60)
print(f"Baseline (current):       {t_baseline*1000:.3f} ms  1.00x")
print(f"Opt A (hoist buf):        {t_opt_a*1000:.3f} ms  {t_opt_a/t_baseline:.2f}x")
print(f"Opt B (add offset):       {t_opt_b*1000:.3f} ms  {t_opt_b/t_baseline:.2f}x")
print(f"Opt C (A+B):              {t_opt_c*1000:.3f} ms  {t_opt_c/t_baseline:.2f}x")
print(f"Opt D (C+_ptdp cache):    {t_opt_d*1000:.3f} ms  {t_opt_d/t_baseline:.2f}x")
print(f"Opt E (A+B+_ptdp cache):  {t_opt_e*1000:.3f} ms  {t_opt_e/t_baseline:.2f}x")

# Which to implement?
best = min(t_opt_a, t_opt_b, t_opt_c, t_opt_d, t_opt_e)
if best == t_opt_a:
    print("\n>>> IMPLEMENT: Hoist _payload_buf = buf out of loop")
if best == t_opt_b:
    print("\n>>> IMPLEMENT: Use addition instead of multiply for _payload_off")
if best == t_opt_c:
    print("\n>>> IMPLEMENT: Both A and B combined")
if best == t_opt_d:
    print("\n>>> IMPLEMENT: All optimizations combined")
if best == t_opt_e:
    print("\n>>> IMPLEMENT: Minimal safe set")