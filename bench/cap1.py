#!/usr/bin/env python3
"""Disassemble individual 32-bit little-endian hex words with Capstone.
Usage: python cap1.py <hexword> [<hexword> ...]  (e.g. 1e202008)
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for h in sys.argv[1:]:
    w = int(h, 16)
    b = w.to_bytes(4, "little")
    got = list(md.disasm(b, 0x1000))
    if got:
        i = got[0]
        print(f"{h}: {i.mnemonic} {i.op_str}")
    else:
        print(f"{h}: (undecoded)")
