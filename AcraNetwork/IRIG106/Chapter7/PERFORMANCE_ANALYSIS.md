# Performance Analysis: `get_aligned_payload` Method

## Overview
The `get_aligned_payload` method (lines 589-777) is heavily used for extracting Ethernet packets from incoming data. It's a complex generator that processes PTFR (PTD packet Frame) payloads and extracts individual PTDP packets.

## Current Optimizations Already in Place

1. **Precomputed lookup tables** (lines 74-98): Avoids IntEnum metaclass overhead per decode
2. **Fill pattern caching** (lines 102-123): Caches compiled regex patterns keyed by Golay instance and fill_word
3. **Fast-path fill detection** (lines 648-704): Detects runs of fill packets with a single regex match
4. **Lazy payload copying** (lines 278-283 in PTDP): Only copies payload when actually accessed
5. **C extension fallback** (lines 311-345): Uses C code when available for Golay decode

## Identified Performance Bottlenecks

### 1. **Regex Matching in Tight Loop** (line 655)
```python
run_match = self._fill_run_re.match(buf)
```
- **Issue**: Regex operations have ~1-2μs overhead even for simple patterns
- **Impact**: Performed every loop iteration for every PTFR
- **Suggestion**: Pre-scan with `str.find()` or byte comparison instead of regex for the simple fixed pattern

### 2. **Complex Offset Bookkeeping State Machine** (lines 627-772)
```python
offset_check_count = 0
aligned = True
is_llp = self.llp
do_offset_check = True
byte_offset = ...
```
- **Issue**: 5 state variables tracked in a complex state machine with ~8 different branches
- **Impact**: Multiple conditional checks per packet; hard to optimize branch prediction
- **Suggestion**: Consider flattening the state machine with explicit states instead of boolean flags

### 3. **Redundant Buffer Slicing Operations**
Multiple locations:
- Line 703: `buf = buf[run_bytes:]`
- Line 709: `buf = self._ptdp.unpack(buf)`
- Line 751: `buf = buf[1:]`
- Line 758: `buf = self.payload[self.ptdp_offset:]`

- **Issue**: Buffer slicing creates new bytes objects; each slice copies data
- **Impact**: For large payloads, this can cause O(n²) copying behavior
- **Suggestion**: Use memoryviews or indices instead of slicing:

```python
# Instead of: buf = buf[run_bytes:]
buf_start = run_bytes
# Track consumption via index, not slice the buffer
```

### 4. **PTDP Object Reuse and Updates** (lines 694-701)
```python
self._ptdp.length = 2
self._ptdp.fragment = PTDPFragment.COMPLETE
self._ptdp.content = PTDPContent.FILL
self._ptdp._payload_buf = buf
self._ptdp._payload_off = _fill_i * fill_len_total + 6
self._ptdp._payload_cache = None
yield (self._ptdp, bytes(), "")
```
- **Issue**: Updates all object attributes for EVERY fill packet
- **Impact**: Attribute access overhead per packet; `_payload_cache` recreation
- **Suggestion**: Only update fields that changed; skip cache=None since we're using buf+offset directly

### 5. **Fill Pattern Run Detection** (lines 658-704)
```python
run_match = self._fill_run_re.match(buf)
if run_match is not None:
    run_bytes = run_match.end()
    fill_len_total = self._fill_len2_total
    run_count = run_bytes // fill_len_total
```
- **Issue**: Regex match for pattern repetition, then integer division
- **Impact**: Two passes over the data (regex + loop) when one is sufficient
- **Suggestion**: Use `finditer()` and count matches, or iterate byte-by-byte with direct comparison

### 6. **LLP Packet Handling Complexity** (lines 744-769)
```python
if is_llp:  # If this is a low latency packet
    next_llp = buf[0]
    if next_llp == 0xFF:
        is_llp = True
        buf = buf[1:]
        byte_offset += len_p + 1
    else:
        is_llp = False
        if ((remainder == bytes()) and self.ptdp_offset > 0) or first_PTFR:
            buf = self.payload[self.ptdp_offset :]
            # ... complex offset logic
```
- **Issue**: Complex nested if-else for LLP sequence handling
- **Impact**: Many conditional checks per packet in LLP sequences
- **Suggestion**: Extract LLP handling to a separate small function for clarity and better branch prediction

### 7. **Offset Check State Transitions** (lines 670-692)
```python
for _fill_i in range(run_count):
    if do_offset_check and byte_offset >= 0:
        do_offset_check = False
        offset_check_count += 1
    elif not do_offset_check and offset_check_count < 1:
        do_offset_check = True
        byte_offset += fill_len_total
    else:
        byte_offset += fill_len_total
```
- **Issue**: State machine with non-monotonic behavior (can enable/disable check multiple times)
- **Impact**: Makes code harder to optimize and introduces extra branches
- **Suggestion**: Simplify to ensure `do_offset_check` is at most flipped once per packet

### 8. **Yield Overhead in Hot Path** (lines 701, 775)
```python
yield (self._ptdp, bytes(), "")
# ... later
yield (self._ptdp, bytes(), "")
```
- **Issue**: Tuple creation and generator yield for EVERY packet
- **Impact**: For high-throughput Ethernet traffic (Gbps), this adds up
- **Suggestion**: Consider batching yields for consecutive packets, or use a different API

### 9. **Repeated `self.payload` Access** (line 611, 617, 758)
```python
buf = self.payload[self.ptdp_offset :]
```
- **Issue**: `self.payload` is a bytes property with getter overhead
- **Impact**: Multiple accesses per PTFR instead of once
- **Suggestion**: Cache `self.payload` in a local variable at the start

### 10. **Nested Conditional Complexity**
Multiple levels of nesting:
- Lines 607-633: 4 nested if-elif blocks for buf selection
- Lines 636-741: Multiple offset check branches
- Lines 744-769: Complex LLP handling

- **Issue**: High cyclomatic complexity (estimated 15+)
- **Impact**: Hard to maintain, poor CPU cache locality, hard to optimize
- **Suggestion**: Refactor into smaller helper functions

## Potential Optimization Strategies

### High-Impact Changes (Recommended)
1. **Replace regex with direct byte comparison** for fill pattern detection
2. **Use indices instead of buffer slicing** to avoid copying
3. **Cache `self.payload` locally**
4. **Reduce offset state machine complexity**

### Medium-Impact Changes
5. **Extract LLP handling to a small helper function**
6. **Simplify offset check logic**
7. **Optimize PTDP updates** for fill packets

### Low-Impact Changes
8. **Consider batching yields** (only if throughput is critical)
9. **Refactor for better locality**
10. **Profile to identify actual bottlenecks** - may find that simple changes help the most

## Profiling Recommendations

Before optimizing, profile the actual usage to identify:
1. What percentage of time is spent in fill packet detection vs normal packets?
2. What percentage of data is LLP packets vs normal packets?
3. What's the typical PTFR size vs number of PTDP packets?
4. Where are the actual hotspots?

Run:
```bash
python -m cProfile -s cumulative test/your_test.py
```

Then use `pstats` or `snakeviz` for visualization.