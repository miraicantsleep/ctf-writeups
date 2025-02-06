import struct, zlib

def brute_force_crc():
    target_crc = 0x48454845
    for w in range(1, 10000):
        for h in range(1, 10000):
            ihdr = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
            if zlib.crc32(b'IHDR' + ihdr) & 0xFFFFFFFF == target_crc:
                return w, h
    return None, None

width, height = brute_force_crc()
print(f"Correct dimensions: {width}x{height}" if width else "No match found")