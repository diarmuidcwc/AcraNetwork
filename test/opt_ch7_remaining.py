"""
Benchmark remaining optimization opportunities in get_aligned_payload.

Candidates:
1. Cache self._ptdp locally (saves attribute lookup per fill packet)
2. Hoist _payload_buf = buf out of fill loop
3. Cache all self._ attributes locally
4. Simplify offset bookkeeping (compute final offset without loop)
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

# Create a PTFR with fill packets
ptfr = PTFR()
ptfr.length = 2000
ptfr.payload = fill_pattern * 200  # 200 fill packets
ptfr.ptdp_offset = 0

buf = fill_pattern * 200
run_match = run_re.match(buf)
run_bytes = run_match.end()
run_count = run_bytes // fill_len
fill_len_total = fill_len

n = 5000

# ===================== BASELINE: Current code =====================
def baseline():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    count = 0
    for _fill_i in range(run_count):
        if True:
            pass  # offset bookkeeping (simplified)
        _ptdp.length = 2
        _ptdp.fragment = PTDPFragment.COMPLETE
        _ptdp.content = PTDPContent.FILL
        _ptdp.low_latency = False
        _ptdp._payload_buf = b
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

t_baseline = timeit.timeit(baseline, number=n)
print(f"Baseline (current):  {t_baseline*1000:.3f} ms")

# ===================== OPT 1: Cache self._ptdp locally =====================
# In the current code, self._ptdp is accessed via attribute lookup each time.
# Caching it locally avoids the attribute lookup.

def opt_cache_ptdp():
    p = ptfr
    b = buf
    _ptdp = p._ptdp  # <-- cache locally
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp.fragment = PTDPFragment.COMPLETE
        _ptdp.content = PTDPContent.FILL
        _ptdp.low_latency = False
        _ptdp._payload_buf = b
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

t_opt1 = timeit.timeit(opt_cache_ptdp, number=n)
print(f"Opt 1 (cache _ptdp):  {t_opt1*1000:.3f} ms  ({t_opt1/t_baseline:.2f}x)")

# ===================== OPT 2: Hoist _payload_buf out of loop =====================
# _payload_buf = buf sets the same buffer ref every time (buf doesn't change
# during the fill run). Only _payload_off changes per iteration.

def opt_hoist_buf():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b  # <-- hoisted out of loop
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp.fragment = PTDPFragment.COMPLETE
        _ptdp.content = PTDPContent.FILL
        _ptdp.low_latency = False
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

t_opt2 = timeit.timeit(opt_hoist_buf, number=n)
print(f"Opt 2 (hoist buf):   {t_opt2*1000:.3f} ms  ({t_opt2/t_baseline:.2f}x)")

# ===================== OPT 3: Hoist buf + skip cache =====================
# _payload_cache = None is needed but we can combine with hoisting.

def opt_hoist_skip_cache():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

t_opt3 = timeit.timeit(opt_hoist_skip_cache, number=n)
print(f"Opt 3 (hoist+skip):  {t_opt3*1000:.3f} ms  ({t_opt3/t_baseline:.2f}x)")

# ===================== OPT 4: Cache all self._ attributes =====================
# Cache _fill_run_re, _fill_len2_total, discard_fill, _ptdp locally

def opt_all_cached():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

t_opt4 = timeit.timeit(opt_all_cached, number=n)
print(f"Opt 4 (all cached):  {t_opt4*1000:.3f} ms  ({t_opt4/t_baseline:.2f}x)")

# ===================== OPT 5: Simplify offset bookkeeping =====================
# The state machine transitions once then stays in steady state.
# We can compute the final offset without a per-packet loop.

def offset_simple():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    byte_offset = 0
    do_offset_check = True
    offset_check_count = 0
    count = 0

    for _fill_i in range(run_count):
        # Current state machine
        if do_offset_check and byte_offset >= 0:
            do_offset_check = False
            offset_check_count += 1
        elif not do_offset_check and offset_check_count < 1:
            do_offset_check = True
            byte_offset += fill_len_total
        else:
            byte_offset += fill_len_total

        _ptdp.length = 2
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count, byte_offset

def offset_hoisted():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    byte_offset = 0
    do_offset_check = True
    offset_check_count = 0
    count = 0

    # First packet handles state machine
    if do_offset_check and byte_offset >= 0:
        do_offset_check = False
        offset_check_count += 1
    elif not do_offset_check and offset_check_count < 1:
        do_offset_check = True
        byte_offset += fill_len_total
    else:
        byte_offset += fill_len_total

    # Remaining packets: steady state, just add offset
    if run_count > 1:
        # Packet 1 already handled above, so we need to add offset for
        # the remaining packets and handle the state machine for packet 2
        for _fill_i in range(1, run_count):
            if do_offset_check and byte_offset >= 0:
                do_offset_check = False
                offset_check_count += 1
            elif not do_offset_check and offset_check_count < 1:
                do_offset_check = True
                byte_offset += fill_len_total
            else:
                byte_offset += fill_len_total

            _ptdp.length = 2
            _ptdp._payload_off = _fill_i * fill_len_total + 6
            _ptdp._payload_cache = None
            count += 1
    return count, byte_offset

n_small = 2000
t_simple = timeit.timeit(offset_simple, number=n_small)
t_hoisted = timeit.timeit(offset_hoisted, number=n_small)
print(f"\nOffset bookkeeping:")
print(f"  Per-packet:  {t_simple*1000:.3f} ms")
print(f"  Hoisted:     {t_hoisted*1000:.3f} ms  ({t_hoisted/t_simple:.2f}x)")

# ===================== OPT 6: Pre-compute payload_off increment =====================
# _payload_off = _fill_i * fill_len_total + 6
# This is i * 8 + 6 for each iteration. The multiplication is cheap but
# we could use addition: _payload_off += fill_len_total

def opt_mul():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp._payload_off = _fill_i * fill_len_total + 6
        _ptdp._payload_cache = None
        count += 1
    return count

def opt_add():
    p = ptfr
    b = buf
    _ptdp = p._ptdp
    _ptdp._payload_buf = b
    _ptdp._payload_off = 6  # First packet offset
    count = 0
    for _fill_i in range(run_count):
        _ptdp.length = 2
        _ptdp._payload_cache = None
        count += 1
        _ptdp._payload_off += fill_len_total  # Add for next packet
    return count

t_mul = timeit.timeit(opt_mul, number=n)
t_add = timeit.timeit(opt_add, number=n)
print(f"\nPayload offset calculation:")
print(f"  Multiply:  {t_mul*1000:.3f} ms")
print(f"  Addition:  {t_add*1000:.3f} ms  ({t_add/t_mul:.2f}x)")

# ===================== SUMMARY =====================
print("\n" + "=" * 60)
print("FINDINGS")
print("=" * 60)
print(f"Baseline (current):           {t_baseline*1000:.3f} ms")
print(f"Opt 1 (cache _ptdp):         {t_opt1*1000:.3f} ms  ({t_opt1/t_baseline:.2f}x)")
print(f"Opt 2 (hoist buf):           {t_opt2*1000:.3f} ms  ({t_opt2/t_baseline:.2f}x)")
print(f"Opt 3 (hoist+skip attrs):    {t_opt3*1000:.3f} ms  ({t_opt3/t_baseline:.2f}x)")
print(f"Opt 4 (all cached):          {t_opt4*1000:.3f} ms  ({t_opt4/t_baseline:.2f}x)")
print(f"Offset hoisted:              {t_hoisted*1000:.3f} ms  ({t_hoisted/t_simple:.2f}x)")
print(f"Payload offset (add):        {t_add*1000:.3f} ms  ({t_add/t_mul:.2f}x)")