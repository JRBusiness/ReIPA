#!/usr/bin/env bash
# Reproducible benchmark: ReIPA vs native reference tools on a Mach-O binary.
#
# Measures three axes, each with a fair native competitor:
#   1. Full arm64 disassembly (decode + format all of __text) ... vs llvm-objdump
#   2. Objective-C class dump (metadata recovery) ............... vs rabin2 -c
#   3. Header / load parse (time to first answer) .............. vs rabin2 -I
# Plus decode correctness scored against Capstone (the oracle).
#
# Usage: bench/run.sh <binary> [<binary> ...]
# Requires on PATH: reipa, reipa-bench (cargo build --release), llvm-objdump,
# rabin2 (radare2), python with `capstone`.
set -u

REIPA="${REIPA:-reipa}"
BENCH="${BENCH:-reipa-bench}"
OUT="${OUT:-./bench-out}"
mkdir -p "$OUT"

timer() { # timer <label> <cmd...> -> prints "label: N.NN s", echoes seconds to stdout var
  local label="$1"; shift
  local s e
  s=$(date +%s.%N); "$@" >/dev/null 2>&1; e=$(date +%s.%N)
  awk -v l="$label" "BEGIN{printf \"  %-28s %8.2f s\n\", l, $e-$s}"
}

for bin in "$@"; do
  name=$(basename "$bin")
  echo "=================================================================="
  echo "BINARY: $name  ($(du -h "$bin" | cut -f1))"
  echo "=================================================================="

  echo "[1] Full arm64 disassembly (all of __text -> text)"
  timer "reipa full-disasm" "$BENCH" throughput "$bin" --emit "$OUT/${name}.reipa.asm"
  timer "llvm-objdump -d"    llvm-objdump -d --no-show-raw-insn "$bin"

  echo "[2] Objective-C class dump (metadata recovery)"
  timer "reipa classdump" "$REIPA" classdump "$bin"
  timer "rabin2 -c"       rabin2 -c "$bin"

  echo "[3] Header / load parse (time to first answer)"
  timer "reipa info"  "$REIPA" info "$bin"
  timer "rabin2 -I"   rabin2 -I "$bin"

  echo "[*] Decode correctness vs Capstone oracle"
  "$BENCH" throughput "$bin" --dump "$OUT/${name}.reipa.csv" >/dev/null 2>&1
  python "$(dirname "$0")/compare_capstone.py" "$OUT/${name}.reipa.csv" \
    | sed 's/^/  /'
  echo
done
