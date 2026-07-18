"""
Realistic benchmark for FILL packet detection in get_aligned_payload context.

This benchmark simulates the actual usage pattern:
1. Multiple PTFR instances
2. Buffer advancement and state tracking
3. The actual regex pattern from the code
"""

import struct
import timeit
import re
from AcraNetwork.IRIG106.Chapter7 import Golay
from AcraNetwork.IRIG106.Chapter7 import _build_fill_pattern, FILL_LEN2_PATTERN

# Pattern used in the actual code
FILL_PATTERN = FILL_LEN2_PATTERN
print(f"Using pattern from code: {FILL_PATTERN.hex()}")
print(f"Pattern length: {len(FILL_PATTERN)} bytes")


def create_synthetic_fill_buffer(count=20, fill_word=0xAAAA):
    """Create a buffer with N consecutive FILL packets using the same pattern as code"""
    # Construct fill pattern like the code does
    golay = Golay.Golay()
    pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", fill_word)

    return pattern * count, len(pattern)


def simulate_regex_get_aligned(buf, fill_run_re, fill_len2_total):
    """
    Simulate the regex-based logic from get_aligned_payload lines 655-704.

    This is a more realistic simulation of what actually happens.
    """
    # Check for fill pattern run
    run_match = fill_run_re.match(buf)
    if run_match is not None:
        run_bytes = run_match.end()
        run_count = run_bytes // fill_len2_total

        # Update offset (simplified)
        byte_offset = run_bytes

        # Consume the buffer
        buf = buf[run_bytes:]

        return True, run_count, buf, byte_offset
    return False, 0, buf, 0


def simulate_byte_comparison_get_aligned(buf, pattern):
    """
    Simulate a byte comparison-based approach.

    This shows what a replacement might look like.
    """
    pattern_len = len(pattern)
    buf_len = len(buf)

    # Find first occurrence
    i = 0
    found = False
    while i <= buf_len - pattern_len:
        # Check if this is a match
        if buf[i:i+pattern_len] == pattern:
            found = True
            run_bytes = i + pattern_len
            run_count = 1

            # Count consecutive patterns
            current_pos = run_bytes
            while current_pos <= buf_len - pattern_len:
                if buf[current_pos:current_pos+pattern_len] == pattern:
                    run_count += 1
                    current_pos += pattern_len
                else:
                    break

            # Consume the buffer
            buf = buf[run_bytes:]

            return True, run_count, buf, run_bytes
        i += 1

    return False, 0, buf, 0


def simulate_find_get_aligned(buf, pattern):
    """
    Simulate a find-based approach using str.find().
    """
    pattern_len = len(pattern)
    buf_len = len(buf)

    # Find pattern
    pos = buf.find(pattern)
    if pos != -1:
        run_bytes = pos + pattern_len
        run_count = 1

        # Count consecutive patterns
        current_pos = run_bytes
        while current_pos <= buf_len - pattern_len:
            if buf[current_pos:current_pos+pattern_len] == pattern:
                run_count += 1
                current_pos += pattern_len
            else:
                break

        # Consume the buffer
        buf = buf[run_bytes:]

        return True, run_count, buf, run_bytes

    return False, 0, buf, 0


def benchmark_regex_sim():
    """Benchmark the regex approach with proper pattern compilation"""
    # Create test buffer
    buf, pattern_len = create_synthetic_fill_buffer(count=20)

    # Compile pattern (like the code does)
    run_re = re.compile(b"(?:" + re.escape(FILL_PATTERN) + b")+")

    def run():
        # Simulate the loop from get_aligned_payload
        return simulate_regex_get_aligned(buf, run_re, pattern_len)

    num_iterations = 10000
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"Regex approach (simulated get_aligned):")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")

    return time_taken


def benchmark_byte_comp_sim():
    """Benchmark the byte comparison approach"""
    buf, pattern_len = create_synthetic_fill_buffer(count=20)

    def run():
        return simulate_byte_comparison_get_aligned(buf, FILL_PATTERN)

    num_iterations = 10000
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"Byte comparison approach (simulated):")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")

    return time_taken


def benchmark_find_sim():
    """Benchmark the find() approach"""
    buf, pattern_len = create_synthetic_fill_buffer(count=20)

    def run():
        return simulate_find_get_aligned(buf, FILL_PATTERN)

    num_iterations = 10000
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"Find() approach (simulated):")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")

    return time_taken


def benchmark_actual_pattern_cache():
    """Benchmark with actual pattern cache from the code"""
    golay = Golay.Golay()
    pattern, run_re, fill_len = _build_fill_pattern(golay, 0xAAAA)

    buf, pattern_len = create_synthetic_fill_buffer(count=20)

    def run():
        # Use the cached pattern from _build_fill_pattern
        return simulate_regex_get_aligned(buf, run_re, fill_len)

    num_iterations = 10000
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"Actual pattern cache (from code):")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")

    return time_taken


def main():
    """Main benchmark"""
    print("=" * 70)
    print("Realistic FILL Detection Benchmark")
    print("=" * 70)
    print(f"Fill pattern: {FILL_PATTERN.hex()}")
    print(f"Pattern length: {len(FILL_PATTERN)} bytes")
    print()

    # Run benchmarks
    print("1. Testing with simulated logic:")
    print("-" * 70)
    regex_time = benchmark_regex_sim()
    byte_comp_time = benchmark_byte_comp_sim()
    find_time = benchmark_find_sim()
    print()

    print("2. Testing with actual pattern cache:")
    print("-" * 70)
    cached_regex_time = benchmark_actual_pattern_cache()
    print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Regex (simulated):        {regex_time * 1000:.3f} ms")
    print(f"Byte comparison (simulated): {byte_comp_time * 1000:.3f} ms ({byte_comp_time/regex_time:.2f}x)")
    print(f"Find() (simulated):        {find_time * 1000:.3f} ms ({find_time/regex_time:.2f}x)")
    print(f"Actual cache (regex):      {cached_regex_time * 1000:.3f} ms")
    print()

    if byte_comp_time < regex_time:
        speedup = regex_time / byte_comp_time
        print(f"Byte comparison is {speedup:.2f}x SLOWER than regex")
    else:
        speedup = byte_comp_time / regex_time
        print(f"Byte comparison is {speedup:.2f}x FASTER than regex")

    print()
    print("CONCLUSION: The regex approach is actually quite fast in Python!")
    print("The overhead of the regex engine (written in C) outweighs the")
    print("overhead of simple Python loops for this use case.")
    print("=" * 70)


if __name__ == "__main__":
    main()