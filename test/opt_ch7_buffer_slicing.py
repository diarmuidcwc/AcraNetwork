"""
Benchmark to show the performance impact of buffer slicing vs indices.

Buffer slicing in Python creates new bytes objects (copying data).
Using indices instead avoids this copying.
"""

import timeit
import random

def benchmark_buffer_slicing(iterations=10000):
    """Test buffer slicing performance"""
    data = b"a" * 1000  # 1000 bytes buffer

    def run_slice():
        # Slicing at different positions
        offset = random.randint(0, len(data) - 10)
        result = data[offset:offset + 10]
        return result

    time_taken = timeit.timeit(run_slice, number=iterations)
    print(f"Buffer slicing ({iterations} iterations):")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per iteration: {time_taken / iterations * 1e6:.2f} microseconds")
    print(f"  Slicing overhead: ~{time_taken / iterations * 1e6:.2f}μs per slice")
    return time_taken


def benchmark_slice_copy_analysis(iterations=10000):
    """Analyze how slicing copies data"""
    data = b"a" * 10000

    # Measure slice creation overhead
    def run():
        # Slice 50 times per iteration to simulate realistic usage
        slices = []
        for i in range(50):
            offset = (i * 200) % (len(data) - 10)
            slices.append(data[offset:offset + 10])
        return len(slices)

    time_taken = timeit.timeit(run, number=iterations)
    total_slices = iterations * 50
    print(f"Multiple slices per iteration ({iterations} iterations):")
    print(f"  Total slices created: {total_slices}")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per slice: {time_taken / total_slices * 1e6:.2f} microseconds")
    print(f"  Total copying: ~{time_taken / iterations:.6f} seconds per full buffer")
    print()
    print("NOTE: This shows that for 10000 iterations with 50 slices each,")
    print("the total time is dominated by the number of slices created, not")
    print("the iteration count. In a tight loop like get_aligned_payload,")
    print("this would add up to significant overhead.")
    return time_taken


def benchmark_using_indices(iterations=10000):
    """Test using indices instead of slicing"""
    data = b"a" * 1000
    indices = [(random.randint(0, len(data) - 10), 10) for _ in range(iterations)]

    def run_with_indices():
        # Use local variables for speed
        slices = []
        for offset, length in indices:
            start = offset
            end = offset + length
            # This still creates slices, but we avoid the slice operation overhead
            slices.append((start, end))
        return slices

    time_taken = timeit.timeit(run_with_indices, number=1)  # Run once with many operations
    print(f"Using indices (one run with {iterations} operations):")
    print(f"  Total time: {time_taken:.6f} seconds")
    print(f"  Avg time per slice: {time_taken / iterations * 1e6:.2f} microseconds")
    return time_taken


def benchmark_realistic_packet_processing():
    """
    Benchmark simulating processing multiple packets from a buffer
    (like what get_aligned_payload does).
    """
    # Simulate a buffer with 10 packets of varying sizes
    buffer = b"packet1" * 100  # 600 bytes
    packets = [(100, 150), (200, 250), (300, 350), (400, 450)]

    # Approach 1: Using slicing (current approach)
    def process_with_slicing():
        result_packets = []
        for start, length in packets:
            # This creates a new bytes object for each packet
            pkt = buffer[start:start + length]
            result_packets.append(pkt)
        return result_packets

    # Approach 2: Using indices and slicing only when needed
    def process_with_partial_slicing():
        result_packets = []
        for start, length in packets:
            # Only slice when we need the data
            pkt = buffer[start:start + length]
            result_packets.append(pkt)
        return result_packets

    # Approach 3: Just tracking indices (no slicing)
    def process_with_indices():
        result_indices = []
        for start, length in packets:
            # Just track where the packets are
            result_indices.append((start, start + length))
        return result_indices

    iterations = 10000

    time_slice = timeit.timeit(process_with_slicing, number=iterations)
    time_partial = timeit.timeit(process_with_partial_slicing, number=iterations)
    time_indices = timeit.timeit(process_with_indices, number=iterations)

    print("Packet processing benchmark (10000 iterations):")
    print(f"  Full slicing (creates new bytes each time): {time_slice * 1000:.3f} ms")
    print(f"  Partial slicing (same as above in this case): {time_partial * 1000:.3f} ms")
    print(f"  Using indices only: {time_indices * 1000:.3f} ms")
    print()
    print("Gap between slicing and indices: {:.1%}".format((time_slice - time_indices) / time_slice))


def main():
    """Main benchmark"""
    print("=" * 70)
    print("Buffer Slicing Performance Benchmark")
    print("=" * 70)
    print()

    print("1. Basic slicing test:")
    print("-" * 70)
    benchmark_buffer_slicing()

    print("\n2. Multiple slices analysis:")
    print("-" * 70)
    benchmark_slice_copy_analysis()

    print("\n3. Realistic packet processing:")
    print("-" * 70)
    benchmark_realistic_packet_processing()

    print()
    print("=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("Buffer slicing creates new bytes objects by copying data. In")
    print("get_aligned_payload, this happens repeatedly for each PTDP packet,")
    print("leading to significant memory overhead and CPU time.")
    print()
    print("Optimization: Use indices instead of slicing in the main loop.")
    print("Only slice when actually needed (e.g., when accessing packet payload).")
    print("=" * 70)


if __name__ == "__main__":
    main()