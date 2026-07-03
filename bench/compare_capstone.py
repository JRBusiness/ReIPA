#!/usr/bin/env python3
"""Score ReIPA's arm64 decoder against Capstone on a real __text section.

Input: a CSV produced by `reipa-bench throughput <bin> --dump <csv>` with one
line per 4-byte word: `addr_hex,word_hex,reipa_mnemonic`. ReIPA emits the
mnemonic `.word` for anything it does not decode.

We reconstruct the raw instruction bytes from the words, disassemble them with
Capstone (the engine behind radare2/objection/many tools), and report:

  * decode coverage  - fraction of words each tool turns into a real insn
  * agreement        - where both decode, do the mnemonic families match
  * ReIPA gaps       - words ReIPA left as .word but Capstone decoded, bucketed
                       by Capstone mnemonic (shows what ISA ReIPA is missing)
  * Capstone throughput for the same bytes (wall-clock, native engine)

Usage: python compare_capstone.py <reipa_dump.csv> [--base 0xADDR]
"""
import sys
import time
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("capstone not installed: pip install capstone")

# Alias groups: Capstone and ReIPA legitimately spell the same instruction
# differently. Treat members of a group as equal for agreement scoring.
ALIASES = [
    {"mov", "movz", "movn", "orr", "movk"},   # mov synthesized from orr/movz/movn
    {"cmp", "subs"}, {"cmn", "adds"}, {"tst", "ands"},
    {"cset", "cinc", "csinc"}, {"csetm", "cinv", "csinv"}, {"cneg", "csneg"},
    {"ret", "br"}, {"bl", "blr"},
    {"lsl", "ubfm", "lsr", "asr", "sbfm", "ubfiz", "sbfiz", "ubfx", "sbfx", "bfi", "bfxil", "bfm"},
    {"neg", "sub"}, {"ngc", "sbc"}, {"mul", "madd"}, {"mneg", "msub"},
    {"mvn", "orn"}, {"nop", "hint"},
    # exact condition-code spellings (ARM defines these as equal):
    {"b.cs", "b.hs"}, {"b.cc", "b.lo"}, {"negs", "subs"}, {"ngcs", "sbcs"},
]

# Capstone's placeholder mnemonic for bytes it cannot decode (SKIPDATA mode).
SKIP_MNEMONIC = ".skip"
def canon(m):
    m = m.lower()
    for g in ALIASES:
        if m in g:
            return "|".join(sorted(g))
    return m

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    csv_path = sys.argv[1]
    base = None
    if "--base" in sys.argv:
        base = int(sys.argv[sys.argv.index("--base") + 1], 16)

    addrs, words, reipa = [], bytearray(), []
    with open(csv_path, "r") as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) != 3:
                continue
            a = int(parts[0], 16)
            w = int(parts[1], 16)
            addrs.append(a)
            words += w.to_bytes(4, "little")
            reipa.append(parts[2])
    n = len(addrs)
    if n == 0:
        sys.exit("empty dump")
    if base is None:
        base = addrs[0]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    # Resync on 4-byte boundaries so Capstone attempts EVERY word, matching
    # ReIPA's linear-sweep decoder. Without this, disasm() halts at the first
    # undecodable word and only covers a contiguous prefix.
    md.skipdata = True
    md.skipdata_setup = (SKIP_MNEMONIC, lambda buffer, size, offset, ud: 4, None)

    # Disassemble in 16 MB windows (4-byte aligned) so Capstone's bulk
    # allocation stays bounded on large binaries; instructions are independent
    # and word-aligned, so chunking at a 4-byte boundary is exact.
    buf = bytes(words)
    CHUNK = 4_000_000 * 4  # 16 MB
    t0 = time.perf_counter()
    cap = {}  # addr -> mnemonic (real instructions only)
    for cstart in range(0, len(buf), CHUNK):
        chunk = buf[cstart:cstart + CHUNK]
        caddr = base + cstart
        for insn in md.disasm(chunk, caddr):
            if insn.mnemonic != SKIP_MNEMONIC:
                cap[insn.address] = insn.mnemonic
    t1 = time.perf_counter()
    cap_secs = t1 - t0
    cap_minsn_s = (len(cap) / cap_secs) / 1e6 if cap_secs else 0.0

    reipa_decoded = sum(1 for m in reipa if m != ".word")
    cap_decoded = len(cap)

    both = agree = 0
    reipa_gap = Counter()      # ReIPA .word, Capstone decoded (missing ISA)
    reipa_extra = 0            # ReIPA decoded, Capstone did not (data / over-eager)
    disagree_samples = Counter()
    for i, a in enumerate(addrs):
        rm = reipa[i]
        cm = cap.get(a)
        if rm != ".word" and cm is not None:
            both += 1
            if canon(rm) == canon(cm):
                agree += 1
            else:
                disagree_samples[f"{rm} vs {cm}"] += 1
        elif rm == ".word" and cm is not None:
            reipa_gap[cm] += 1
        elif rm != ".word" and cm is None:
            reipa_extra += 1

    print(f"words                : {n}")
    print(f"ReIPA decoded        : {reipa_decoded}  ({100*reipa_decoded/n:.1f}%)")
    print(f"Capstone decoded     : {cap_decoded}  ({100*cap_decoded/n:.1f}%)")
    print(f"both decoded         : {both}")
    print(f"  mnemonic agree     : {agree}  ({100*agree/both:.2f}% of both)")
    print(f"  mnemonic disagree  : {both-agree}  ({100*(both-agree)/both:.2f}% of both)")
    print(f"ReIPA .word, Cap real: {sum(reipa_gap.values())}  (ReIPA ISA gaps)")
    print(f"ReIPA real, Cap none : {reipa_extra}")
    print(f"Capstone throughput  : {cap_minsn_s:.2f} Minsn/s  ({cap_secs*1000:.1f} ms for {len(cap)} insns)")
    print("\ntop ReIPA ISA gaps (Capstone mnemonic ReIPA left as .word):")
    for m, c in reipa_gap.most_common(15):
        print(f"  {c:>9}  {m}")
    if disagree_samples:
        print("\ntop mnemonic disagreements (after alias normalization):")
        for s, c in disagree_samples.most_common(12):
            print(f"  {c:>9}  {s}")

if __name__ == "__main__":
    main()
