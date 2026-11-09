#!/usr/bin/env python3
"""Verify 4-byte alignment of uncompressed entries without zipalign.

zipalign pads stored entries so their file data starts on a 4-byte boundary.
This checks the same property directly from the central directory, which makes
the guarantee verifiable even when build-tools are unavailable.
"""
import sys
import zipfile

ALIGNMENT = 4


def main(path):
    bad, checked = [], 0
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or info.compress_type != zipfile.ZIP_STORED:
                continue
            checked += 1
            raw = z.open(info)
            try:
                offset = info.header_offset
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    head = fh.read(30)
                    import struct
                    name_len, extra_len = struct.unpack_from("<HH", head, 26)
                data_offset = offset + 30 + name_len + extra_len
            finally:
                raw.close()
            if data_offset % ALIGNMENT:
                bad.append((info.filename, data_offset % ALIGNMENT))
    print(f"stored entries checked: {checked}")

    def critical(name):
        # These are memory-mapped at runtime: misalignment breaks installs or
        # mmap-based loading. Other entries are reported but not fatal.
        return name in ("resources.arsc", "AndroidManifest.xml") or name.endswith(".so")

    crit = [b for b in bad if critical(b[0])]
    other = [b for b in bad if not critical(b[0])]

    if other:
        print(f"non-critical misaligned entries: {len(other)} (first 5)")
        for name, rem in other[:5]:
            print(f"  {name} -> offset % {ALIGNMENT} == {rem}")
    if crit:
        print(f"CRITICAL misaligned entries: {len(crit)} (first 10)")
        for name, rem in crit[:10]:
            print(f"  {name} -> offset % {ALIGNMENT} == {rem}")
        return 1
    print(f"all critical entries start on {ALIGNMENT}-byte boundaries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
