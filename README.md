# ReIPA: iOS Mach-O disassembler & decompiler in Rust

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#building)
[![GitHub stars](https://img.shields.io/github/stars/JRBusiness/REipa?style=social)](https://github.com/JRBusiness/REipa/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/JRBusiness/REipa?style=social)](https://github.com/JRBusiness/REipa/network/members)

**ReIPA** is a fast iOS reverse-engineering toolkit written in Rust: a Mach-O
loader, an arm64 (AArch64) disassembler, Objective-C and Swift metadata
recovery, a decompiler, and a native desktop explorer. It reads decrypted
App Store `.ipa` / Mach-O binaries directly, with **no dependency on Ghidra,
IDA Pro, radare2, or LLVM**.

> **Why not Ghidra-based tools?** Many iOS decompilers wrap the Ghidra engine,
> which means a JVM, a multi-gigabyte install, and minutes of analysis per large
> binary. ReIPA is a self-contained native binary that parses Mach-O, arm64, and
> Objective-C/Swift metadata itself, so a class dump that takes `rabin2` a minute
> or two finishes in a couple of seconds.

If you need Android instead, see the sister project: **[REapk](https://github.com/JRBusiness/REapk)**.

![ReIPA desktop app screenshot](image.png)

<!--
Keywords: iOS decompiler, Mach-O parser, arm64 disassembler, AArch64,
IPA reverse engineering, Objective-C class-dump, Swift demangling,
class-dump alternative, Ghidra alternative, IDA Pro alternative,
radare2 alternative, Rust reverse engineering, iOS static analysis.
-->

## Why it exists

The usual tools for this job are either slow on the large binaries that ship in
modern apps, or they pull in a heavy framework you have to install and manage.
ReIPA parses the Mach-O itself, walks the Objective-C and Swift metadata itself,
and decodes arm64 itself. On a 300 MB DoorDash binary it dumps every
Objective-C class in a couple of seconds, where `rabin2 -c` takes a minute or
two.

## Features

- **Mach-O loader:** headers, load commands, segments, symbols, dyld info,
  chained fixups, and FairPlay (`cryptid`) detection.
- **arm64 / AArch64 disassembler:** 100% decode coverage on `__text`,
  validated against Capstone on full App Store binaries.
- **Objective-C class dump:** `@interface` output with typed ivars, methods,
  protocols, and categories; resolves external superclasses via dyld binds.
- **Swift metadata recovery:** types and demangling from `__swift5_*`.
- **Decompiler:** CFG construction, condition recovery, if/else and loop
  structuring, and function naming from Objective-C method implementations.
- **Native desktop GUI:** searchable class browser, jump-to-decompile,
  syntax-highlighted disassembly and pseudocode, and an optional AI chat panel.

## How it compares

|                         | **ReIPA**            | Ghidra              | IDA Pro        |
| ----------------------- | -------------------- | ------------------- | -------------- |
| Engine                  | Native Rust          | JVM                 | Native         |
| Install size            | Single binary        | Multi-GB            | Commercial     |
| External dependencies   | **None**             | Java                | n/a            |
| Reads `.ipa` directly   | ✅                   | ❌                  | ❌             |
| Objective-C class dump  | ✅ (typed ivars)     | partial             | ✅ (plugin)    |
| Swift metadata          | ✅                   | partial             | partial        |
| FairPlay detection      | ✅                   | ❌                  | ❌             |
| Price                   | Free (MIT)           | Free                | $$$            |

ReIPA does not aim to replace a full Ghidra/IDA workflow. It aims to be the
*fast first pass*: open a 300 MB App Store binary, dump every class, and start
reading decompiled functions in seconds instead of minutes.

## Benchmarks

Measured against the installed tools through the `reipa-bench` harness. The
arm64 decoder is validated at **100% decode coverage** against Capstone on full
App Store binaries.

| Task                         | ReIPA vs baseline    | Baseline tool     |
| ---------------------------- | -------------------- | ----------------- |
| Full `__text` disassembly    | **~9-12x faster**    | `llvm-objdump`    |
| Objective-C class dump       | **~24-44x faster**   | `rabin2 -c`       |
| Header / load-command info   | **~38-55x faster**   | `rabin2 -I`       |

On a 300 MB DoorDash binary, ReIPA dumps every Objective-C class in a couple of
seconds where `rabin2 -c` takes a minute or two.

## Building

You need a recent stable Rust toolchain.

```
cargo build --release
```

The CLI lands at `target/release/reipa`. The desktop app is `reipa-gui`, and it
shells out to the `reipa` and `reipa-bench` executables, so keep all three in
the same directory (the release build already does this).

## Command-line use

Run `verify` first to check whether the binary is decrypted:

```
reipa verify      MyApp.ipa
reipa info        MyApp.ipa
reipa symbols     MyApp.ipa
reipa strings     MyApp.ipa
reipa objc        MyApp.ipa
reipa classdump   MyApp.ipa
reipa swift-types MyApp.ipa
reipa disasm      MyApp.ipa 0x100004380
reipa decompile   MyApp.ipa 0x100004380
```

`disasm` and `decompile` take a start address and stop at the function's return
or an instruction cap (`--count`, default 256 and 512 respectively).

### A note on FairPlay

App Store binaries are encrypted until the device decrypts them at launch. If
`__TEXT` is still ciphertext, disassembly produces garbage, so `verify` checks
the `cryptid` flag and says so plainly. To analyze an encrypted binary, dump a
decrypted copy from a device first (frida-ios-dump, bagbak, and similar) and run
ReIPA against that.

## Desktop app

`reipa-gui` is a native window built on egui. Open an `.ipa` and it extracts the
executable for you; open a raw Mach-O and it reads it directly. It has:

- A dark theme by default, with a light toggle in the top bar.
- Tabs for header info, classes (a searchable sidebar with an `@interface` view
  and a per-method jump-to-decompile), Swift types, strings, disassembly, and
  the decompiler.
- Syntax highlighting on the disassembly and pseudocode views.
- A FairPlay banner that runs `verify` on open so you know up front whether the
  binary is decrypted.
- A chat panel on the right that talks to the `claude` or `codex` CLI if you
  have one installed. It can send the current view (a decompiled function, a
  class dump, the header) along as context, so you can ask questions about what
  you are looking at without copying and pasting.

The heavy parsing runs on a background thread, so the window stays responsive
while a 250 MB binary loads.

## Limitations

The decompiler is working but still in early development. It builds a CFG,
recovers conditions from flag-setting instructions, structures if/else and loops
where it can prove the region is clean, and names functions from Objective-C
method implementations. What it does not have yet: full SSA, type recovery, and
register-level variable naming.

Other known gaps: arm64e pointer authentication in chained fixups is not
decoded, Swift protocol names with punycode or complex generics fall back to
their raw mangled form, and imported-module parent pointers in Swift type
descriptors are not dereferenced.

## Tests

```
cargo test --workspace
```

The arm64 decoder, the Objective-C and Swift metadata paths, and the loader all
have unit and snapshot coverage. The decoder is additionally validated against
Capstone on full binaries through the benchmark harness.

## License

MIT. See [LICENSE](LICENSE).
