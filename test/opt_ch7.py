"""
Benchmark test for FILL packet detection optimization.

This test creates synthetic FILL packets and benchmarks:
1. The current regex-based approach
2. A suggested byte-comparison approach
"""

import struct
import timeit
from AcraNetwork.IRIG106.Chapter7 import Golay

# Pattern: golay.encode(0) + golay.encode(2) + fill_word (2 bytes)
# From Chapter7/__init__.py, FILL_LEN2_PATTERN = b"\x00\x00\x00\x00)>\\xaa\\xaa"
# But we should construct it properly: 3 bytes + 3 bytes + 2 bytes = 8 bytes

FILL_LEN2_PATTERN = b"\x00\x00\x00\x00)>\\xaa\\xaa"

# Let's construct the pattern properly using golay encoding
def construct_fill_pattern(fill_word=0xAAAA):
    """Construct a FILL packet pattern using proper Golay encoding"""
    golay = Golay.Golay()

    # Encode the values
    encoded0 = golay.encode(0, as_string=True)  # 3 bytes
    encoded2 = golay.encode(2, as_string=True)  # 3 bytes
    fill_bytes = struct.pack(">H", fill_word)    # 2 bytes

    return encoded0 + encoded2 + fill_bytes


# Create the actual fill pattern (should be 8 bytes)
FILL_PATTERN = construct_fill_pattern()
print(f"Fill pattern: {FILL_PATTERN.hex()}")
print(f"Fill pattern length: {len(FILL_PATTERN)} bytes")


def create_synthetic_fill_packets(count=20):
    """Create a buffer with N consecutive FILL packets"""
    golay = Golay.Golay()
    fill_pattern = construct_fill_pattern()

    # Each FILL packet is 8 bytes
    packet_size = len(fill_pattern)

    # Create a buffer with 20 fill packets (160 bytes total)
    buffer = fill_pattern * count

    print(f"Created buffer with {count} FILL packets ({len(buffer)} bytes)")
    return buffer, packet_size


def benchmark_regex_approach(data, num_iterations=10000):
    """
    Current approach using regex to detect FILL packets.
    This mimics the logic from get_aligned_payload().
    """
    import re

    # Compile the pattern once (simulating the cache)
    pattern = re.compile(b"(?:" + re.escape(FILL_PATTERN) + b")+")

    def run():
        # Scan for runs of FILL packets
        run_match = pattern.match(data)
        if run_match is not None:
            run_bytes = run_match.end()
            fill_len_total = len(FILL_PATTERN)
            run_count = run_bytes // fill_len_total

            # Advance the buffer
            remaining = data[run_bytes:]
            return True, run_count, remaining
        return False, 0, data

    # Run benchmark
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"\nRegex approach:")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")
    print(f"  Throughput: {len(data) * num_iterations / time_taken / 1024:.2f} KB/s")

    return time_taken


def benchmark_byte_comparison_approach(data, num_iterations=10000):
    """
    Suggested approach using direct byte comparison.

    This iterates through the buffer and looks for the pattern using
    direct byte comparisons instead of regex.
    """
    fill_pattern = FILL_PATTERN
    fill_len = len(fill_pattern)

    def run():
        # Get data length
        data_len = len(data)

        # Find the pattern using direct comparison
        i = 0
        while i <= data_len - fill_len:
            # Check if we have a full match at position i
            match = True
            for j in range(fill_len):
                if data[i + j] != fill_pattern[j]:
                    match = False
                    break

            if match:
                # Found a FILL packet - count consecutive ones
                run_bytes = i + fill_len

                # Advance the buffer
                remaining = data[run_bytes:]
                return True, run_bytes // fill_len, remaining

            i += 1

        # No FILL packets found
        return False, 0, data

    # Run benchmark
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"\nByte comparison approach:")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")
    print(f"  Throughput: {len(data) * num_iterations / time_taken / 1024:.2f} KB/s")

    return time_taken


def benchmark_byte_search_approach(data, num_iterations=10000):
    """
    Alternative approach using string.find().

    This uses Python's built-in string search which is optimized in C.
    """
    fill_pattern = FILL_PATTERN

    def run():
        # Use find() to locate the pattern
        pos = data.find(fill_pattern)
        if pos != -1:
            # Found FILL packets
            run_bytes = pos + len(fill_pattern)
            remaining = data[run_bytes:]
            # Count consecutive packets
            run_count = 1
            current_pos = run_bytes
            while current_pos <= len(data) - len(fill_pattern):
                # Quick check if next bytes match
                if data[current_pos:current_pos + len(fill_pattern)] == fill_pattern:
                    run_count += 1
                    current_pos += len(fill_pattern)
                else:
                    break

            return True, run_count, remaining
        return False, 0, data

    # Run benchmark
    time_taken = timeit.timeit(run, number=num_iterations)

    print(f"\nByte search (find) approach:")
    print(f"  Iterations: {num_iterations}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / num_iterations * 1e6:.2f} microseconds")
    print(f"  Throughput: {len(data) * num_iterations / time_taken / 1024:.2f} KB/s")

    return time_taken


def main():
    """Main benchmark function"""
    print("=" * 70)
    print("FILL Packet Detection Performance Benchmark")
    print("=" * 70)

    # Create synthetic data
    print("\n1. Creating synthetic FILL packets...")
    buffer, packet_size = create_synthetic_fill_packets(count=20)
    print(f"   Pattern: {FILL_PATTERN.hex()}")
    print(f"   Packet size: {packet_size} bytes")
    print(f"   Total buffer size: {len(buffer)} bytes")

    # Run benchmarks
    print("\n2. Running benchmarks...")
    print("-" * 70)

    num_iterations = 10000
    regex_time = benchmark_regex_approach(buffer[:len(buffer)//2], num_iterations)  # Half size for more reps

    # Create fresh buffer for other benchmarks
    buffer = FILL_PATTERN * 20
    byte_comp_time = benchmark_byte_comparison_approach(buffer, num_iterations)

    byte_search_time = benchmark_byte_search_approach(buffer, num_iterations)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Regex approach:     {regex_time * 1000:.3f} ms ({regex_time/byte_comp_time:.2f}x)")
    print(f"Byte comparison:    {byte_comp_time * 1000:.3f} ms (baseline)")
    print(f"Byte search (find): {byte_search_time * 1000:.3f} ms ({byte_search_time/byte_comp_time:.2f}x)")
    print()

    if byte_comp_time < regex_time:
        speedup = regex_time / byte_comp_time
        print(f"✓ Byte comparison is {speedup:.2f}x FASTER than regex")
    else:
        speedup = byte_comp_time / regex_time
        print(f"✗ Byte comparison is {speedup:.2f}x SLOWER than regex")

    if byte_search_time < regex_time:
        speedup = regex_time / byte_search_time
        print(f"✓ Byte search (find) is {speedup:.2f}x FASTER than regex")
    else:
        speedup = byte_search_time / regex_time
        print(f"✗ Byte search (find) is {speedup:.2f}x SLOWER than regex")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()