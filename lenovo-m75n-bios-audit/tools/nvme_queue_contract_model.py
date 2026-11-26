#!/usr/bin/env python3
"""Synthetic serialized NVMe admin SQ doorbell arithmetic, not a hardware emulator."""

def first_mismatch(hw_depth, sw_count, submissions=300):
    if hw_depth < 2 or not 2 <= sw_count <= hw_depth:
        raise ValueError("unsupported depth")
    tail = 0
    for number in range(1, submissions + 1):
        old_tail = tail
        tail = (tail + 1) % sw_count
        delta = (tail - old_tail) % hw_depth
        if delta != 1:
            return (number, old_tail, tail, delta)
    return None

if __name__ == "__main__":
    for name, hw, sw in [("1.24 example", 256, 256), ("1.32/1.33 initial", 64, 63), ("1.32/1.33 recovery", 63, 63)]:
        print(name, hw, sw, first_mismatch(hw, sw))
    assert first_mismatch(256, 256) is None
    assert first_mismatch(64, 63) == (63, 62, 0, 2)
    assert first_mismatch(63, 63) is None
