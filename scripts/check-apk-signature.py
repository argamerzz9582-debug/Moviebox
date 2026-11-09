#!/usr/bin/env python3
"""Structural signature check used when apksigner is unavailable.

Parses the ZIP, locates the "APK Sig Block 42" magic, reads the v2 signer block
id, and confirms the v1 digest manifest exists. This proves the APK carries a
v2/v3 signing block; it is not a substitute for apksigner's verification, and
the report says so.
"""
import struct
import sys
import zipfile

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def find_eocd(data):
    # EOCD is within the last 64 KiB + 22 bytes; scan backwards.
    start = max(0, len(data) - (0xFFFF + 22))
    i = data.rfind(b"PK\x05\x06", start)
    if i < 0:
        raise ValueError("no end-of-central-directory record")
    return i


def main(path):
    with open(path, "rb") as fh:
        data = fh.read()
    eocd = find_eocd(data)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]

    print(f"file: {path}")
    print(f"size: {len(data)} bytes")

    if data[cd_offset - 16:cd_offset] != APK_SIG_BLOCK_MAGIC:
        print("no APK Signing Block found before the central directory")
        return 1

    size_of_block = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    block_start = cd_offset - size_of_block - 8
    if block_start < 0:
        print("signing block claims a size larger than the file")
        return 1
    header_size = struct.unpack_from("<Q", data, block_start)[0]
    print(f"APK Signing Block: {size_of_block} bytes at offset {block_start}")
    print(f"block header size matches: {header_size == size_of_block}")

    ids = set()
    pos = block_start + 8
    end = cd_offset - 24
    while pos + 12 <= end:
        pair_len = struct.unpack_from("<Q", data, pos)[0]
        if pair_len < 4 or pos + 8 + pair_len > end:
            break
        block_id = struct.unpack_from("<I", data, pos + 8)[0]
        ids.add(block_id)
        pos += 8 + pair_len

    print("signer scheme ids: " + ", ".join(f"0x{i:08X}" for i in sorted(ids)))
    v2 = V2_BLOCK_ID in ids
    v3 = V3_BLOCK_ID in ids
    print(f"v2 scheme block: {'present' if v2 else 'absent'}")
    print(f"v3 scheme block: {'present' if v3 else 'absent'}")

    with zipfile.ZipFile(path) as z:
        names = {n.lower() for n in z.namelist()}
    v1 = any(n.startswith("meta-inf/") and n.endswith((".sf", ".rsa", ".dsa", ".ec"))
             for n in names)
    print(f"v1 signature files: {'present' if v1 else 'absent'}")

    if not (v1 or v2 or v3):
        print("no signing material found")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
