# ReIPA Benchmark — vs llvm-objdump, radare2/rabin2, Capstone

**What this measures.** ReIPA is a from-scratch iOS Mach-O loader + arm64
disassembler + ObjC/Swift metadata extractor. This benchmark compares it, on
real decrypted App Store binaries, against the reference tools actually
installed on the test machine — on the specific jobs ReIPA is built for:
linear disassembly, Objective-C class dump, and header/load parsing. Decode
**correctness** is scored against Capstone as an oracle.

**Honesty notes.**
- Every number for ReIPA, llvm-objdump, rabin2, and Capstone below was
  measured on this machine. Reproduce with `bench/run.sh <binary>`.
- Ghidra, IDA Pro/Hex-Rays, Hopper, and Binary Ninja are **not installed
  here**, so they are discussed qualitatively (clearly labeled) — no invented
  timings.
- These tools are **not all doing the same job**. llvm-objdump, rabin2, and
  Capstone are disassemblers/extractors like ReIPA. Ghidra/IDA/Hopper/BN are
  full *decompilers* with pseudocode, type inference, and xref databases —
  ReIPA does not yet compete with them on decompiler completeness. The point
  here is throughput on load/disassemble/metadata, which is where the "Ghidra
  is slow on IPAs" complaint originates.

## Test corpus

| Binary   | App                     | Size  | `__text` instructions |
|----------|-------------------------|-------|-----------------------|
| TWorld   | T-Mobile Tuesdays 11.8  | 177 MB| 30,659,398            |
| UAGame   | proximabeta UAMO (Unreal game) | 216 MB| 42,017,482     |
| DoorDash | DoorDash Consumer 8.10  | 274 MB| 52,497,113            |

All arm64, decrypted. Machine: Windows 11, native release builds of every tool.

---

## Axis 1 — Full arm64 disassembly (decode + format all of `__text` → text)

Same work both sides: decode every instruction and emit a text line. ReIPA via
`reipa-bench throughput --emit`; llvm-objdump via `llvm-objdump -d`. (llvm also
disassembles `__stubs`/`__stub_helper`, ~0.05–0.2% more lines.)

| Binary   | ReIPA    | llvm-objdump | ReIPA speedup |
|----------|----------|--------------|---------------|
| TWorld   | 10.88 s  | 102.17 s     | **9.4×**      |
| UAGame   | 17.32 s  | 210.83 s     | **12.2×**     |
| DoorDash | 20.57 s  | 244.03 s     | **11.9×**     |

Pure decode throughput (no text emitted): **3.6–4.0 M instructions/sec**
single-threaded.

## Axis 2 — Objective-C class dump (metadata recovery)

`reipa classdump` vs `rabin2 -c`. Both walk `__objc_classlist` and emit classes,
methods, and ivars.

| Binary   | ReIPA   | rabin2 -c | ReIPA speedup | ReIPA classes / methods / ivars |
|----------|---------|-----------|---------------|---------------------------------|
| TWorld   | 0.82 s  | 19.57 s   | **23.9×**     | 4,748 / 4,908 / 27,678          |
| UAGame   | 0.28 s  | 12.37 s   | **44.2×**     | 1,669 / 25,423 / 6,836          |
| DoorDash | 1.13 s  | 30.83 s   | **27.3×**     | 10,085 / 37,160 / 46,149        |

ReIPA resolves **100% of superclasses** on all three (chained-fixups aware):
`named_super == classes` in every run.

## Axis 3 — Header / load parse (time to first answer)

`reipa info` vs `rabin2 -I`. (rabin2 also hashes the whole file / computes
entropy, so part of its cost is extra work — but it is the standard "tell me
about this binary" command.)

| Binary   | ReIPA info | rabin2 -I | ReIPA speedup |
|----------|------------|-----------|---------------|
| TWorld   | 0.226 s    | 8.72 s    | **38.6×**     |
| UAGame   | 0.239 s    | 8.61 s    | **36.0×**     |
| DoorDash | 0.289 s    | 15.74 s   | **54.5×**     |

---

## Decode correctness vs Capstone (oracle)

Capstone (the engine behind radare2, objection, and many RE tools) disassembles
every 4-byte word in `__text`; we compare mnemonics word-for-word. "Coverage" =
fraction of words the tool turns into a real instruction. "Agreement" = of the
words *both* decode, how often the mnemonic matches (after normalizing exact
aliases like `b.cs`≡`b.hs`, `mov`≡`orr`/`movz`).

| Binary   | ReIPA coverage | Capstone coverage | Agreement (both decode) |
|----------|----------------|-------------------|-------------------------|
| TWorld   | **100.0%**     | 100.0%            | **100.00%** (1 diff)    |
| UAGame   | **100.0%**     | 100.0%            | **100.00%** (49 diff)   |
| DoorDash | **100.0%**     | 100.0%            | **100.00%** (2 diff)    |

**Reading these numbers.** Capstone reaches ~100% because nearly every 32-bit
word is *some* valid AArch64 encoding — including bytes that are actually data
(literal pools, jump tables) decoded as junk. So 100% linear coverage is not by
itself a quality signal. What matters is that **where ReIPA decodes, it now
agrees with Capstone on 100.00% of instructions** (rounded; the raw
disagreement counts are 1 / 49 / 2 out of 30–52 million), and the leftover
`.word` residue is a few hundred-to-few-thousand words of genuine data plus a
handful of exotic system encodings.

This is the result of completing the AArch64 decoder against the
`bench/compare_capstone.py` oracle. ReIPA started at 94–95% coverage / 99.7%
agreement; the gap was closed by adding the missing families the oracle
flagged — **logical-immediate** (`DecodeBitMasks`), **signed loads**
(`ldrsw`/`ldrsb`), **FP scalar** (`fmov`/`fadd`/`fmul`/`fcmp`/`fcvt*`),
**atomics/exclusives** (`stlxr`/`ldaxr`/`ldar`), and the full **NEON vector**
set (three-same, three-different, by-indexed-element, copy/`dup`, permute
`zip`/`uzp`/`trn`, two-register-misc, shifts, `movi`, and structure loads).
A critical fix along the way: constraining the SIMD `V` bit (bit 26) in the
integer load/store masks, which had been silently mis-decoding 128-bit
`ldr`/`str`/`ldp` as signed byte loads.

### Reproducing the correctness score

```
reipa-bench throughput <binary> --dump out.csv   # dumps addr,word,mnemonic
python bench/compare_capstone.py out.csv          # scores vs Capstone
```

---

## Where ReIPA does not compete (honest scope)

| Tool          | Installed here? | What it does that ReIPA does not |
|---------------|-----------------|----------------------------------|
| **Ghidra**    | No              | Full auto-analysis + C decompiler. On a 200 MB arm64 binary its auto-analysis is minutes-to-tens-of-minutes (the original motivation for ReIPA). Not measured here. |
| **IDA/Hex-Rays** | No           | Best-in-class decompiler, type propagation, interactive DB. ReIPA's pseudocode is a first-cut, not Hex-Rays quality. |
| **Hopper / Binary Ninja** | No  | Full decompilers with xrefs, ILs, plugins. |
| **radare2 (r2)** | Yes (rabin2 used) | Full analysis engine, scripting, patching. ReIPA is a targeted extractor, not an analysis platform. |

**Summary.** For the narrow, high-value loop of *load an iOS binary and get
disassembly + ObjC/Swift metadata out fast*, ReIPA is ~**10× faster than
llvm-objdump** at disassembly, ~**25–45× faster than rabin2** at class dump, and
~**35–55× faster** at header parsing, while decoding the instructions it covers
with **~99.7% fidelity** to Capstone. It does **not** replace a full decompiler
(Ghidra/IDA/Hopper/BN); it targets the part of the workflow those tools are
slowest at.

## Reproducing

```
cd reipa && cargo build --release          # builds reipa + reipa-bench
bench/run.sh <path-to-macho> [<more> ...]   # runs all axes + Capstone scoring
```

Requires on PATH: `llvm-objdump`, `rabin2` (radare2), and `python` with
`capstone` installed (`pip install capstone`).
