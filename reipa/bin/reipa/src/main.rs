use clap::{Parser, Subcommand};
use reipa_image::Image;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "reipa", about = "ReIPA Mach-O loader")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report encryption status and basic sanity checks (run this first).
    Verify { path: PathBuf },
    /// Header, segments, UUID, symbol/string counts.
    Info { path: PathBuf },
    /// List symbols with addresses.
    Symbols { path: PathBuf },
    /// List __cstring strings with addresses.
    Strings { path: PathBuf },
    /// List Objective-C string pools: selectors, class names, method types.
    Objc { path: PathBuf },
    /// Dump Objective-C classes recovered from __objc_classlist.
    Classdump { path: PathBuf },
    /// List Swift nominal types from __swift5_types (classes, structs, enums).
    SwiftTypes { path: PathBuf },
    /// Disassemble arm64 code. With an address, decode one function; otherwise dump all of __text.
    Disasm {
        path: PathBuf,
        /// Start virtual address, e.g. 0x100abcdef. Omit to dump all of __text.
        addr: Option<String>,
        /// Max instructions when an address is given (default 256).
        #[arg(long, default_value_t = 256)]
        count: usize,
    },
    /// First-cut decompile: CFG-structured pseudocode for a function.
    Decompile {
        path: PathBuf,
        /// Function start virtual address.
        addr: String,
        #[arg(long, default_value_t = 512)]
        count: usize,
    },
}

fn read_input(path: &PathBuf) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.starts_with(b"PK\x03\x04") {
        return Err(
            "input looks like a .ipa (zip); reipa operates on a raw Mach-O \
                    executable. Extract Payload/<App>.app/<Executable> from the .ipa first."
                .to_string(),
        );
    }
    Ok(bytes)
}

fn uuid_string(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

fn dm(name: &str) -> String {
    reipa_swift::demangle(name)
}

fn imp_note(imp: u64) -> String {
    if imp == 0 {
        String::new()
    } else {
        format!("  // 0x{imp:x}")
    }
}

fn render_method(selector: &str, types: &str) -> String {
    if types.is_empty() {
        selector.to_string()
    } else {
        reipa_objc::type_encoding::method_signature(selector, types)
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { path } => {
            let bytes = read_input(&path)?;
            let img = Image::load(&bytes).map_err(|e| e.to_string())?;
            let arch =
                if img.macho.cpusubtype & 0x00ff_ffff == reipa_macho::consts::CPU_SUBTYPE_ARM64E {
                    "arm64e"
                } else {
                    "arm64"
                };
            println!("arch:       {arch}");
            println!("filetype:   0x{:x}", img.macho.filetype);
            println!("segments:   {}", img.macho.segments.len());
            if img.macho.is_encrypted() {
                println!("ENCRYPTED:  YES (cryptid=1) — FairPlay-protected.");
                println!("            __TEXT is ciphertext; decompilation is impossible");
                println!("            until decrypted. Obtain a decrypted dump (e.g.");
                println!("            frida-ios-dump / bagbak) and retry.");
            } else {
                println!("ENCRYPTED:  no — ready for analysis.");
            }
            Ok(())
        }
        Command::Info { path } => {
            let bytes = read_input(&path)?;
            let img = Image::load(&bytes).map_err(|e| e.to_string())?;
            println!("cputype:    0x{:x}", img.macho.cputype);
            println!("cpusubtype: 0x{:x}", img.macho.cpusubtype);
            println!("filetype:   0x{:x}", img.macho.filetype);
            match &img.macho.uuid {
                Some(u) => println!("uuid:       {}", uuid_string(u)),
                None => println!("uuid:       (none)"),
            }
            println!("segments:   {}", img.macho.segments.len());
            for s in &img.macho.segments {
                println!(
                    "  {} vm=0x{:x} size=0x{:x} sections={}",
                    s.segname,
                    s.vmaddr,
                    s.vmsize,
                    s.sections.len()
                );
            }
            println!("symbols:    {}", img.macho.symbols.len());
            println!("strings:    {}", img.strings.len());
            println!("func starts:{}", img.macho.function_starts.len());
            if let Some(f0) = img.macho.function_starts.first() {
                let sample: Vec<String> = img
                    .macho
                    .function_starts
                    .iter()
                    .take(3)
                    .map(|a| format!("0x{a:x}"))
                    .collect();
                println!("  first funcs: {} ...", sample.join(", "));
                let _ = f0;
            }
            println!("chained fixups: {}", img.macho.has_chained_fixups);
            Ok(())
        }
        Command::Symbols { path } => {
            let bytes = read_input(&path)?;
            let img = Image::load(&bytes).map_err(|e| e.to_string())?;
            for s in &img.macho.symbols {
                if !s.name.is_empty() {
                    println!("0x{:016x} {}", s.value, dm(&s.name));
                }
            }
            Ok(())
        }
        Command::Strings { path } => {
            let bytes = read_input(&path)?;
            let img = Image::load(&bytes).map_err(|e| e.to_string())?;
            for s in &img.strings {
                println!("0x{:016x} {}", s.addr, s.value);
            }
            Ok(())
        }
        Command::Objc { path } => {
            let bytes = read_input(&path)?;
            let objc = reipa_objc::parse_objc_strings(&bytes).map_err(|e| e.to_string())?;
            println!("selectors:    {}", objc.selectors.len());
            println!("class names:  {}", objc.class_names.len());
            println!("method types: {}", objc.method_types.len());
            println!("--- selectors ---");
            for s in &objc.selectors {
                println!("0x{:016x} {}", s.addr, s.value);
            }
            println!("--- class names ---");
            for s in &objc.class_names {
                println!("0x{:016x} {}", s.addr, s.value);
            }
            println!("--- method types ---");
            for s in &objc.method_types {
                println!("0x{:016x} {}", s.addr, s.value);
            }
            Ok(())
        }
        Command::Classdump { path } => {
            let bytes = read_input(&path)?;
            let classes = reipa_objc::parse_objc_classes(&bytes).map_err(|e| e.to_string())?;
            let total_methods: usize = classes.iter().map(|c| c.instance_methods.len()).sum();
            println!(
                "// {} classes, {} instance methods\n",
                classes.len(),
                total_methods
            );
            for c in &classes {
                let protos = if c.protocols.is_empty() {
                    String::new()
                } else {
                    let ps: Vec<String> = c.protocols.iter().map(|p| dm(p)).collect();
                    format!(" <{}>", ps.join(", "))
                };
                match &c.superclass {
                    Some(sup) => println!("@interface {} : {}{}", dm(&c.name), dm(sup), protos),
                    None => println!("@interface {}{}", dm(&c.name), protos),
                }
                if !c.ivars.is_empty() {
                    println!("{{");
                    for iv in &c.ivars {
                        let ty = reipa_objc::type_encoding::decode_type(&iv.type_enc);
                        println!("    {} {}; // +0x{:x}", ty, iv.name, iv.offset);
                    }
                    println!("}}");
                }
                for m in &c.class_methods {
                    println!("+ {};{}", render_method(&m.name, &m.types), imp_note(m.imp));
                }
                for m in &c.instance_methods {
                    println!("- {};{}", render_method(&m.name, &m.types), imp_note(m.imp));
                }
                println!("@end\n");
            }

            let categories =
                reipa_objc::parse_objc_categories(&bytes).map_err(|e| e.to_string())?;
            if !categories.is_empty() {
                println!("// {} categories\n", categories.len());
                for cat in &categories {
                    let cls = cat
                        .class_name
                        .as_deref()
                        .map(dm)
                        .unwrap_or_else(|| "?".to_string());
                    let protos = if cat.protocols.is_empty() {
                        String::new()
                    } else {
                        let ps: Vec<String> = cat.protocols.iter().map(|p| dm(p)).collect();
                        format!(" <{}>", ps.join(", "))
                    };
                    println!("@interface {} ({}){}", cls, cat.name, protos);
                    for m in &cat.class_methods {
                        println!("+ {};", render_method(&m.name, &m.types));
                    }
                    for m in &cat.instance_methods {
                        println!("- {};", render_method(&m.name, &m.types));
                    }
                    println!("@end\n");
                }
            }
            Ok(())
        }
        Command::SwiftTypes { path } => {
            use reipa_swift::metadata::SwiftKind;
            let bytes = read_input(&path)?;
            let types =
                reipa_swift::metadata::parse_swift_types(&bytes).map_err(|e| e.to_string())?;
            println!("// {} Swift types", types.len());
            for t in &types {
                let kw = match t.kind {
                    SwiftKind::Class => "class",
                    SwiftKind::Struct => "struct",
                    SwiftKind::Enum => "enum",
                    SwiftKind::Other => "type",
                };
                println!("{kw} {}", t.name);
            }
            Ok(())
        }
        Command::Disasm { path, addr, count } => {
            use std::io::Write;
            let bytes = read_input(&path)?;
            let macho = reipa_macho::MachOImage::parse(&bytes).map_err(|e| e.to_string())?;
            let slice = reipa_macho::fat::select_arm64_slice(&bytes).map_err(|e| e.to_string())?;
            let sdata = slice.data;
            match addr {
                Some(addr) => {
                    let start = addr.strip_prefix("0x").unwrap_or(&addr);
                    let mut cur = u64::from_str_radix(start, 16)
                        .map_err(|_| format!("bad address: {addr}"))?;
                    for _ in 0..count {
                        let off = match macho.vmaddr_to_offset(cur) {
                            Some(o) => o,
                            None => {
                                eprintln!("(address 0x{cur:x} not in a mapped segment)");
                                break;
                            }
                        };
                        let word = match reipa_macho::reader::Reader::at(sdata, off)
                            .ok()
                            .and_then(|mut r| r.read_u32().ok())
                        {
                            Some(w) => w,
                            None => break,
                        };
                        let insn = reipa_arm64::decode(word, cur);
                        println!("0x{:x}:  {:08x}  {}", cur, word, insn.text);
                        if insn.flow == reipa_arm64::Flow::Return {
                            break;
                        }
                        cur = cur.wrapping_add(4);
                    }
                    Ok(())
                }
                None => {
                    let text = macho
                        .section_by_name("__text")
                        .ok_or_else(|| "no __text section".to_string())?;
                    let off = text.offset as usize;
                    let size = text.size as usize;
                    let end = off
                        .checked_add(size)
                        .filter(|e| *e <= sdata.len())
                        .ok_or_else(|| "__text out of range".to_string())?;
                    let code = &sdata[off..end];
                    let base = text.addr;
                    let stdout = std::io::stdout();
                    let mut w = std::io::BufWriter::new(stdout.lock());
                    let mut i = 0;
                    while i + 4 <= code.len() {
                        let word =
                            u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);
                        let a = base + i as u64;
                        let insn = reipa_arm64::decode(word, a);
                        let _ = writeln!(w, "0x{:x}:  {:08x}  {}", a, word, insn.text);
                        i += 4;
                    }
                    Ok(())
                }
            }
        }
        Command::Decompile { path, addr, count } => {
            let bytes = read_input(&path)?;
            let macho = reipa_macho::MachOImage::parse(&bytes).map_err(|e| e.to_string())?;
            let slice = reipa_macho::fat::select_arm64_slice(&bytes).map_err(|e| e.to_string())?;
            let sdata = slice.data;
            let start = parse_addr(&addr)?;

            let next_start = macho
                .function_starts
                .iter()
                .copied()
                .filter(|&a| a > start)
                .min();

            let mut insns = Vec::new();
            let mut furthest = start;
            let mut cur = start;
            for _ in 0..count {
                if let Some(ns) = next_start {
                    if cur >= ns {
                        break;
                    }
                }
                let off = match macho.vmaddr_to_offset(cur) {
                    Some(o) => o,
                    None => break,
                };
                let word = match reipa_macho::reader::Reader::at(sdata, off)
                    .ok()
                    .and_then(|mut r| r.read_u32().ok())
                {
                    Some(w) => w,
                    None => break,
                };
                let insn = reipa_arm64::decode(word, cur);
                if let reipa_arm64::Flow::Branch(t) | reipa_arm64::Flow::CondBranch(t) = insn.flow {
                    if t > furthest && next_start.is_none_or(|ns| t < ns) {
                        furthest = t;
                    }
                }
                let is_ret = insn.flow == reipa_arm64::Flow::Return;
                insns.push(insn);
                if is_ret && cur >= furthest {
                    break;
                }
                cur = cur.wrapping_add(4);
            }

            let (names, sigs) = build_names(&bytes);
            let fname = names
                .get(&start)
                .cloned()
                .unwrap_or_else(|| format!("sub_{start:x}"));
            let blocks = reipa_arm64::cfg::build_blocks(&insns);
            let rblocks: Vec<RBlock> = blocks.iter().map(|b| render_block(b, &names)).collect();
            let by_addr: std::collections::HashMap<u64, usize> = rblocks
                .iter()
                .enumerate()
                .map(|(i, rb)| (rb.start, i))
                .collect();
            let order: Vec<u64> = rblocks.iter().map(|rb| rb.start).collect();
            println!(
                "// {fname}  @0x{start:x}  ({} blocks, {} instructions)",
                blocks.len(),
                insns.len()
            );
            if let Some(sig) = sigs.get(&start) {
                println!("// signature: {sig}   [x0=self, x1=_cmd, x2..=args]");
            }
            println!("{fname}() {{");
            let mut out = Vec::new();
            structure_emit(
                &rblocks,
                &by_addr,
                &order,
                &names,
                0,
                order.len(),
                u64::MAX,
                1,
                &mut out,
            );
            for line in out {
                println!("{line}");
            }
            println!("}}");
            Ok(())
        }
    }
}

fn is_reg_tok(s: &str) -> bool {
    s == "sp"
        || ((s.starts_with('x') || s.starts_with('w'))
            && s.len() >= 2
            && s[1..].chars().all(|c| c.is_ascii_digit()))
}

fn is_hex_const(s: &str) -> bool {
    s.strip_prefix("0x").is_some_and(|h| {
        !h.is_empty()
            && h.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    })
}

fn fold_arith(expr: &str) -> String {
    if let Some((a, b)) = expr.split_once(" + ") {
        if is_hex_const(a) && is_hex_const(b) {
            if let (Ok(x), Ok(y)) = (
                u64::from_str_radix(&a[2..], 16),
                u64::from_str_radix(&b[2..], 16),
            ) {
                return format!("0x{:x}", x.wrapping_add(y));
            }
        }
    }
    if let Some((a, n)) = expr.split_once(" << ") {
        if is_hex_const(a) {
            if let (Ok(x), Ok(sh)) = (u64::from_str_radix(&a[2..], 16), n.parse::<u32>()) {
                return format!("0x{:x}", x.wrapping_shl(sh));
            }
        }
    }
    expr.to_string()
}

fn subst_consts(expr: &str, env: &std::collections::HashMap<String, String>) -> String {
    let subbed: Vec<String> = expr
        .split(' ')
        .map(|tok| {
            let core = tok.trim_matches(|c| "*()[],".contains(c));
            if let Some(v) = env.get(core) {
                tok.replace(core, v)
            } else {
                tok.to_string()
            }
        })
        .collect();
    let joined = subbed.join(" ");
    if let Some(inner) = joined.strip_prefix("*(").and_then(|s| s.strip_suffix(')')) {
        format!("*({})", fold_arith(inner))
    } else {
        fold_arith(&joined)
    }
}

fn propagate(stmts: &[String]) -> Vec<String> {
    let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut rendered: Vec<(Option<String>, String)> = Vec::new();
    for s in stmts {
        if let Some((lhs, rhs)) = s.split_once(" = ") {
            if is_reg_tok(lhs) && rhs.ends_with(';') {
                let val = subst_consts(&rhs[..rhs.len() - 1], &env);
                if is_hex_const(&val) {
                    env.insert(lhs.to_string(), val.clone());
                } else {
                    env.remove(lhs);
                }
                rendered.push((Some(lhs.to_string()), format!("{lhs} = {val};")));
                continue;
            }
        }
        let body = s.strip_suffix(';').unwrap_or(s);
        let sub = subst_consts(body, &env);
        rendered.push((
            None,
            if s.ends_with(';') {
                format!("{sub};")
            } else {
                sub
            },
        ));
    }
    let regs_of = |s: &str| -> Vec<String> {
        s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| is_reg_tok(t))
            .map(|t| t.to_string())
            .collect()
    };
    let mut live: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut keep = vec![true; rendered.len()];
    for idx in (0..rendered.len()).rev() {
        let (dest, text) = &rendered[idx];
        if text.contains("()") {
            for n in 0..=7 {
                live.insert(format!("x{n}"));
                live.insert(format!("w{n}"));
            }
        }
        match dest {
            Some(d) => {
                let rhs = text.split_once(" = ").map(|(_, r)| r).unwrap_or("");
                let is_const_def = is_hex_const(rhs.trim_end_matches(';'));
                if is_const_def && !live.contains(d) {
                    keep[idx] = false;
                } else {
                    live.remove(d);
                    for u in regs_of(rhs) {
                        live.insert(u);
                    }
                }
            }
            None => {
                for u in regs_of(text) {
                    live.insert(u);
                }
            }
        }
    }
    rendered
        .into_iter()
        .zip(keep)
        .filter(|(_, k)| *k)
        .map(|((_, t), _)| t)
        .collect()
}

struct RBlock {
    start: u64,
    stmts: Vec<String>,
    term: Term,
    succ: Vec<u64>,
}

fn call_name(t: u64, names: &std::collections::HashMap<u64, String>) -> String {
    names
        .get(&t)
        .cloned()
        .unwrap_or_else(|| format!("sub_{t:x}"))
}

enum Term {
    Ret,
    IndirectRet(String),
    Goto(u64),
    If { cond: String, taken: u64 },
    Fall,
}

fn render_block(
    b: &reipa_arm64::cfg::Block,
    names: &std::collections::HashMap<u64, String>,
) -> RBlock {
    use reipa_arm64::Flow;
    let mut stmts = Vec::new();
    let mut last_flags: Option<&reipa_arm64::FlagOp> = None;
    let mut term = Term::Fall;
    for ins in &b.insns {
        match &ins.flow {
            Flow::Call(t) => {
                stmts.push(format!("{}();", call_name(*t, names)));
            }
            Flow::IndirectCall => stmts.push(pseudo(ins)),
            Flow::Return => term = Term::Ret,
            Flow::Indirect => term = Term::IndirectRet(ins.text.clone()),
            Flow::Branch(t) => term = Term::Goto(*t),
            Flow::CondBranch(t) => {
                let cond = match ins.cond {
                    Some(code) => resolve_cond(code, last_flags),
                    None => cond_of(&ins.text),
                };
                term = Term::If { cond, taken: *t };
            }
            Flow::Fallthrough => {
                if ins.flags.is_some() {
                    last_flags = ins.flags.as_ref();
                } else {
                    stmts.push(pseudo(ins));
                }
            }
        }
    }
    RBlock {
        start: b.start,
        stmts: propagate(&stmts),
        term,
        succ: b.succ.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn structure_emit(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    names: &std::collections::HashMap<u64, String>,
    lo: usize,
    hi: usize,
    follow: u64,
    ind: usize,
    out: &mut Vec<String>,
) {
    let pad = "    ".repeat(ind);
    let mut i = lo;
    while i < hi {
        if let Some((e, lcond, exit)) = detect_do_while(rb, by, order, i, hi) {
            out.push(format!("{pad}do {{"));
            structure_emit(rb, by, order, names, i, e, exit, ind + 1, out);
            let lpad = "    ".repeat(ind + 1);
            for s in &rb[by[&order[e]]].stmts {
                out.push(format!("{lpad}{s}"));
            }
            out.push(format!("{pad}}} while ({lcond});"));
            i = by.get(&exit).copied().unwrap_or(hi);
            continue;
        }
        if let Some((e, wcond, exit)) = detect_while(rb, by, order, i, hi) {
            out.push(format!("{pad}while ({wcond}) {{"));
            structure_emit(rb, by, order, names, i + 1, e + 1, order[i], ind + 1, out);
            out.push(format!("{pad}}}"));
            i = by.get(&exit).copied().unwrap_or(hi);
            continue;
        }
        let block = &rb[by[&order[i]]];
        if is_jump_target(rb, order[i]) {
            out.push(format!(
                "{}L_{:x}:",
                "    ".repeat(ind.saturating_sub(1)),
                order[i]
            ));
        }
        for s in &block.stmts {
            out.push(format!("{pad}{s}"));
        }
        match &block.term {
            Term::Ret => {
                out.push(format!("{pad}return;"));
                i += 1;
            }
            Term::IndirectRet(t) => {
                out.push(format!("{pad}return; // {t}"));
                i += 1;
            }
            Term::Fall => i += 1,
            Term::Goto(t) => {
                if !by.contains_key(t) {
                    out.push(format!("{pad}return {}();", call_name(*t, names)));
                } else if *t != follow || i + 1 != hi {
                    out.push(format!("{pad}goto L_{t:x};"));
                }
                i += 1;
            }
            Term::If { cond, taken } => {
                if !by.contains_key(taken) {
                    out.push(format!(
                        "{pad}if ({cond}) return {}();",
                        call_name(*taken, names)
                    ));
                    i += 1;
                    continue;
                }
                if let Some(plan) = plan_if(rb, by, order, i, hi, *taken, cond) {
                    let inv = invert_cond(cond);
                    match plan {
                        IfPlan::Simple { tidx } => {
                            out.push(format!("{pad}if ({inv}) {{"));
                            structure_emit(rb, by, order, names, i + 1, tidx, *taken, ind + 1, out);
                            out.push(format!("{pad}}}"));
                            i = tidx;
                        }
                        IfPlan::Else { tidx, midx, merge } => {
                            out.push(format!("{pad}if ({inv}) {{"));
                            structure_emit(rb, by, order, names, i + 1, tidx, merge, ind + 1, out);
                            out.push(format!("{pad}}} else {{"));
                            structure_emit(rb, by, order, names, tidx, midx, merge, ind + 1, out);
                            out.push(format!("{pad}}}"));
                            i = midx;
                        }
                    }
                    continue;
                }
                out.push(format!("{pad}if ({cond}) goto L_{taken:x};"));
                i += 1;
            }
        }
    }
}

fn is_invertible(c: &str) -> bool {
    [" == ", " != ", " <= ", " >= ", " < ", " > "]
        .iter()
        .any(|op| c.contains(op))
}

fn invert_cond(c: &str) -> String {
    for (op, inv) in [
        (" == ", " != "),
        (" != ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
    ] {
        if let Some(pos) = c.find(op) {
            return format!("{}{}{}", &c[..pos], inv, &c[pos + op.len()..]);
        }
    }
    format!("!({c})")
}

fn is_jump_target(rb: &[RBlock], addr: u64) -> bool {
    rb.iter().any(|b| {
        matches!(b.term, Term::Goto(t) if t == addr)
            || matches!(&b.term, Term::If { taken, .. } if *taken == addr)
    })
}

enum IfPlan {
    Simple {
        tidx: usize,
    },
    Else {
        tidx: usize,
        midx: usize,
        merge: u64,
    },
}

fn detect_do_while(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    i: usize,
    hi: usize,
) -> Option<(usize, String, u64)> {
    let header = order[i];
    for e in (i..hi).rev() {
        if let Term::If { cond, taken } = &rb[by[&order[e]]].term {
            if *taken == header {
                let exit = *order.get(e + 1)?;
                if by.contains_key(&exit)
                    && loop_ok(rb, by, order, i, e, exit)
                    && is_invertible(cond)
                {
                    return Some((e, cond.clone(), exit));
                }
            }
        }
    }
    None
}

fn detect_while(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    i: usize,
    hi: usize,
) -> Option<(usize, String, u64)> {
    let header = order[i];
    let (hcond, exit) = match &rb[by[&header]].term {
        Term::If { cond, taken } if is_invertible(cond) => (cond.clone(), *taken),
        _ => return None,
    };
    let &eidx = by.get(&exit)?;
    if eidx <= i {
        return None;
    }
    for e in (i + 1..hi.min(eidx)).rev() {
        if !matches!(&rb[by[&order[e]]].term, Term::Goto(t) if *t == header) {
            continue;
        }
        let early = (i + 1..e).any(|k| rb[by[&order[k]]].succ.contains(&header));
        if !early && loop_ok(rb, by, order, i, e, exit) {
            return Some((e, invert_cond(&hcond), exit));
        }
    }
    None
}

fn loop_ok(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    i: usize,
    e: usize,
    exit: u64,
) -> bool {
    for k in i..=e {
        for &s in &rb[by[&order[k]]].succ {
            let internal = by.get(&s).is_some_and(|&si| si >= i && si <= e);
            if !internal && s != exit {
                return false;
            }
        }
    }
    for (idx, addr) in order.iter().enumerate() {
        if idx >= i && idx <= e {
            continue;
        }
        for &s in &rb[by[addr]].succ {
            if by.get(&s).is_some_and(|&si| si > i && si <= e) {
                return false;
            }
        }
    }
    true
}

fn plan_if(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    i: usize,
    hi: usize,
    taken: u64,
    cond: &str,
) -> Option<IfPlan> {
    let &tidx = by.get(&taken)?;
    if !(tidx > i + 1 && tidx <= hi && is_invertible(cond)) {
        return None;
    }
    let guard = order[i];
    if let Term::Goto(merge) = rb[by[&order[tidx - 1]]].term {
        if let Some(&midx) = by.get(&merge) {
            if midx > tidx
                && midx <= hi
                && region_ok(rb, by, order, i + 1, tidx, merge, guard)
                && region_ok(rb, by, order, tidx, midx, merge, guard)
            {
                return Some(IfPlan::Else { tidx, midx, merge });
            }
        }
    }
    if region_ok(rb, by, order, i + 1, tidx, taken, guard) {
        return Some(IfPlan::Simple { tidx });
    }
    None
}

fn region_ok(
    rb: &[RBlock],
    by: &std::collections::HashMap<u64, usize>,
    order: &[u64],
    lo: usize,
    hi: usize,
    exit_addr: u64,
    guard_addr: u64,
) -> bool {
    if lo >= hi || hi > order.len() {
        return false;
    }
    for k in lo..hi {
        for &s in &rb[by[&order[k]]].succ {
            let internal = by.get(&s).is_some_and(|&si| si >= lo && si < hi);
            if !internal && s != exit_addr {
                return false;
            }
        }
    }
    for (idx, addr) in order.iter().enumerate() {
        if idx >= lo && idx < hi {
            continue;
        }
        for &s in &rb[by[addr]].succ {
            if let Some(&si) = by.get(&s) {
                if si > lo && si < hi {
                    return false;
                }
                if si == lo && *addr != guard_addr {
                    return false;
                }
            }
        }
    }
    true
}

const CC: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

fn resolve_cond(code: u8, flags: Option<&reipa_arm64::FlagOp>) -> String {
    use reipa_arm64::FlagKind;
    let f = match flags {
        Some(f) => f,
        None => return format!("cond_{}", CC.get(code as usize).unwrap_or(&"?")),
    };
    match f.kind {
        FlagKind::Cmp => cmp_expr(code, &f.a, &f.b),
        FlagKind::Cmn => cmp_expr(code, &format!("({} + {})", f.a, f.b), "0"),
        FlagKind::Tst => {
            let inner = format!("({} & {})", f.a, f.b);
            match code {
                0 => format!("{inner} == 0"),
                1 => format!("{inner} != 0"),
                _ => format!(
                    "cond_{} /* {inner} */",
                    CC.get(code as usize).unwrap_or(&"?")
                ),
            }
        }
    }
}

fn cmp_expr(code: u8, a: &str, b: &str) -> String {
    let op = match code {
        0 => "==",
        1 => "!=",
        2 => ">=",
        3 | 4 => "<",
        5 | 10 => ">=",
        8 | 12 => ">",
        9 | 13 => "<=",
        11 => "<",
        6 | 7 => return "/* overflow */".to_string(),
        14 => return "1".to_string(),
        15 => return "0".to_string(),
        _ => return format!("cond_{}", CC.get(code as usize).unwrap_or(&"?")),
    };
    format!("{a} {op} {b}")
}

fn parse_addr(addr: &str) -> Result<u64, String> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    u64::from_str_radix(s, 16).map_err(|_| format!("bad address: {addr}"))
}

type NameMap = std::collections::HashMap<u64, String>;

fn build_names(bytes: &[u8]) -> (NameMap, NameMap) {
    let mut names = std::collections::HashMap::new();
    let mut sigs = std::collections::HashMap::new();
    let mut add = |imp: u64, sign: char, cls: &str, cat: Option<&str>, sel: &str, types: &str| {
        if imp == 0 {
            return;
        }
        let disp = match cat {
            Some(c) => format!("{sign}[{cls}({c}) {sel}]"),
            None => format!("{sign}[{cls} {sel}]"),
        };
        names.entry(imp).or_insert(disp);
        sigs.entry(imp)
            .or_insert(format!("{sign} {}", render_method(sel, types)));
    };
    if let Ok(classes) = reipa_objc::parse_objc_classes(bytes) {
        for c in &classes {
            let cls = dm(&c.name);
            for m in &c.instance_methods {
                add(m.imp, '-', &cls, None, &m.name, &m.types);
            }
            for m in &c.class_methods {
                add(m.imp, '+', &cls, None, &m.name, &m.types);
            }
        }
    }
    if let Ok(cats) = reipa_objc::parse_objc_categories(bytes) {
        for cat in &cats {
            let cls = cat
                .class_name
                .as_deref()
                .map(dm)
                .unwrap_or_else(|| "?".to_string());
            for m in &cat.instance_methods {
                add(m.imp, '-', &cls, Some(&cat.name), &m.name, &m.types);
            }
            for m in &cat.class_methods {
                add(m.imp, '+', &cls, Some(&cat.name), &m.name, &m.types);
            }
        }
    }
    (names, sigs)
}

fn pseudo(ins: &reipa_arm64::Insn) -> String {
    use reipa_arm64::Flow;
    match &ins.flow {
        Flow::Return => return "return;".to_string(),
        Flow::Branch(t) => return format!("goto L_{t:x};"),
        Flow::CondBranch(t) => return format!("if ({}) goto L_{t:x};", cond_of(&ins.text)),
        Flow::IndirectCall => {
            let r = ins.text.trim_start_matches("blr ").trim();
            return format!("(*{r})();");
        }
        Flow::Indirect => return format!("goto *; // {}", ins.text),
        Flow::Call(t) => return format!("sub_{t:x}();"),
        Flow::Fallthrough => {}
    }
    let (mn, rest) = match ins.text.split_once(' ') {
        Some((m, r)) => (m, r),
        None => return format!("// {}", ins.text),
    };
    let ops: Vec<&str> = rest.split(", ").collect();
    let noh = |s: &str| s.trim_start_matches('#').to_string();
    let binop = |sym: &str| -> Option<String> {
        if ops.len() >= 3 {
            Some(format!(
                "{} = {} {sym} {};",
                ops[0],
                noh(ops[1]),
                noh(&ops[2..].join(", "))
            ))
        } else {
            None
        }
    };
    let out = match mn {
        "mov" if ops.len() == 2 => format!("{} = {};", ops[0], noh(ops[1])),
        "add" => binop("+").unwrap_or_else(|| fallback(&ins.text)),
        "sub" => binop("-").unwrap_or_else(|| fallback(&ins.text)),
        "orr" => binop("|").unwrap_or_else(|| fallback(&ins.text)),
        "and" => binop("&").unwrap_or_else(|| fallback(&ins.text)),
        "eor" => binop("^").unwrap_or_else(|| fallback(&ins.text)),
        "mul" => binop("*").unwrap_or_else(|| fallback(&ins.text)),
        "udiv" | "sdiv" => binop("/").unwrap_or_else(|| fallback(&ins.text)),
        "lsl" => binop("<<").unwrap_or_else(|| fallback(&ins.text)),
        "lsr" | "asr" => binop(">>").unwrap_or_else(|| fallback(&ins.text)),
        "adrp" | "adr" if ops.len() == 2 => format!("{} = {};", ops[0], ops[1]),
        "ldr" | "ldur" | "ldrb" | "ldrh" if ops.len() >= 2 => {
            format!("{} = *({});", ops[0], mem_inner(&ops[1..].join(", ")))
        }
        "str" | "stur" | "strb" | "strh" if ops.len() >= 2 => {
            format!("*({}) = {};", mem_inner(&ops[1..].join(", ")), ops[0])
        }
        "uxtb" | "uxth" | "sxtb" | "sxth" | "sxtw" if ops.len() == 2 => {
            format!("{} = {};", ops[0], ops[1])
        }
        "csel" if ops.len() == 4 => format!("{} = {} ? {} : {};", ops[0], ops[3], ops[1], ops[2]),
        "cset" if ops.len() == 2 => format!("{} = ({});", ops[0], ops[1]),
        _ => fallback(&ins.text),
    };
    out
}

fn fallback(text: &str) -> String {
    format!("// {text}")
}

fn mem_inner(op: &str) -> String {
    let inner = op.trim_start_matches('[').trim_end_matches(']');
    match inner.split_once(", #") {
        Some((base, off)) => format!("{base} + {off}"),
        None => inner.to_string(),
    }
}

fn cond_of(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("cbz ") {
        let r = rest.split(',').next().unwrap_or("?").trim();
        return format!("{r} == 0");
    }
    if let Some(rest) = text.strip_prefix("cbnz ") {
        let r = rest.split(',').next().unwrap_or("?").trim();
        return format!("{r} != 0");
    }
    if let Some(rest) = text.strip_prefix("tbz ") {
        let mut it = rest.split(',');
        let r = it.next().unwrap_or("?").trim();
        let b = it.next().unwrap_or("#?").trim().trim_start_matches('#');
        return format!("({r} & (1 << {b})) == 0");
    }
    if let Some(rest) = text.strip_prefix("tbnz ") {
        let mut it = rest.split(',');
        let r = it.next().unwrap_or("?").trim();
        let b = it.next().unwrap_or("#?").trim().trim_start_matches('#');
        return format!("({r} & (1 << {b})) != 0");
    }
    if let Some(rest) = text.strip_prefix("b.") {
        let cc = rest.split(' ').next().unwrap_or("?");
        return format!("cond_{cc}");
    }
    "cond".to_string()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn rb(start: u64, stmts: &[&str], term: Term, succ: &[u64]) -> RBlock {
        RBlock {
            start,
            stmts: stmts.iter().map(|s| s.to_string()).collect(),
            term,
            succ: succ.to_vec(),
        }
    }

    #[test]
    fn if_else_recovered_without_fallthrough() {
        let blocks = vec![
            rb(
                0x00,
                &[],
                Term::If {
                    cond: "a == 0".into(),
                    taken: 0x40,
                },
                &[0x40, 0x10],
            ),
            rb(
                0x10,
                &[],
                Term::If {
                    cond: "b == 0".into(),
                    taken: 0x30,
                },
                &[0x30, 0x20],
            ),
            rb(0x20, &["r = 1;"], Term::Goto(0x40), &[0x40]),
            rb(0x30, &["r = 2;"], Term::Fall, &[0x40]),
            rb(0x40, &["x0 = r;"], Term::Ret, &[]),
        ];
        let order: Vec<u64> = blocks.iter().map(|b| b.start).collect();
        let by: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let mut out = Vec::new();
        let names: HashMap<u64, String> = HashMap::new();
        structure_emit(
            &blocks,
            &by,
            &order,
            &names,
            0,
            order.len(),
            u64::MAX,
            1,
            &mut out,
        );
        let text = out.join("\n");
        assert!(text.contains("if (a != 0) {"), "outer if missing:\n{text}");
        assert!(text.contains("} else {"), "if/else not recovered:\n{text}");
        let p1 = text.find("r = 1;").expect("r=1 missing");
        let pe = text.find("} else {").expect("else missing");
        let p2 = text.find("r = 2;").expect("r=2 missing");
        assert!(p1 < pe && pe < p2, "then/else out of order:\n{text}");
        assert!(
            !text.contains("r = 1;\n        r = 2;"),
            "then fell into else:\n{text}"
        );
    }

    #[test]
    fn do_while_loop_recovered() {
        let blocks = vec![
            rb(0x00, &["i = 0;"], Term::Fall, &[0x10]),
            rb(
                0x10,
                &["sum += i;", "i++;"],
                Term::If {
                    cond: "i < 10".into(),
                    taken: 0x10,
                },
                &[0x10, 0x20],
            ),
            rb(0x20, &["x0 = sum;"], Term::Ret, &[]),
        ];
        let order: Vec<u64> = blocks.iter().map(|b| b.start).collect();
        let by: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let mut out = Vec::new();
        let names: HashMap<u64, String> = HashMap::new();
        structure_emit(
            &blocks,
            &by,
            &order,
            &names,
            0,
            order.len(),
            u64::MAX,
            1,
            &mut out,
        );
        let text = out.join("\n");
        assert!(text.contains("do {"), "no do-while:\n{text}");
        assert!(
            text.contains("} while (i < 10);"),
            "wrong loop cond:\n{text}"
        );
        let dopos = text.find("do {").unwrap();
        let whpos = text.find("} while").unwrap();
        let bodypos = text.find("sum += i;").unwrap();
        let exitpos = text.find("x0 = sum;").unwrap();
        assert!(
            dopos < bodypos && bodypos < whpos && whpos < exitpos,
            "loop layout wrong:\n{text}"
        );
    }

    #[test]
    fn while_loop_recovered() {
        let blocks = vec![
            rb(
                0x00,
                &[],
                Term::If {
                    cond: "i >= 10".into(),
                    taken: 0x30,
                },
                &[0x30, 0x10],
            ),
            rb(0x10, &["sum += i;", "i++;"], Term::Goto(0x00), &[0x00]),
            rb(0x30, &["x0 = sum;"], Term::Ret, &[]),
        ];
        let order: Vec<u64> = blocks.iter().map(|b| b.start).collect();
        let by: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let mut out = Vec::new();
        let names: HashMap<u64, String> = HashMap::new();
        structure_emit(
            &blocks,
            &by,
            &order,
            &names,
            0,
            order.len(),
            u64::MAX,
            1,
            &mut out,
        );
        let text = out.join("\n");
        assert!(text.contains("while (i < 10) {"), "no while loop:\n{text}");
        assert!(!text.contains("goto L_0;"), "back-edge not elided:\n{text}");
        let wpos = text.find("while (i < 10)").unwrap();
        let bodypos = text.find("sum += i;").unwrap();
        let exitpos = text.find("x0 = sum;").unwrap();
        assert!(
            wpos < bodypos && bodypos < exitpos,
            "while layout wrong:\n{text}"
        );
    }

    #[test]
    fn propagate_folds_adrp_address() {
        let stmts = vec![
            "x8 = 0x10ce86000;".to_string(),
            "x0 = *(x8 + 0x790);".to_string(),
        ];
        let out = propagate(&stmts);
        assert_eq!(out, vec!["x0 = *(0x10ce86790);".to_string()]);
    }

    #[test]
    fn propagate_folds_add_chain_into_use() {
        let stmts = vec![
            "x2 = 0x10ccca000;".to_string(),
            "x2 = x2 + 0x268;".to_string(),
            "*(x2) = x0;".to_string(),
        ];
        let out = propagate(&stmts);
        assert_eq!(out, vec!["*(0x10ccca268) = x0;".to_string()]);
    }

    #[test]
    fn propagate_keeps_arg_setup_before_call() {
        let stmts = vec!["x0 = 0x1234;".to_string(), "foo();".to_string()];
        let out = propagate(&stmts);
        assert_eq!(out, vec!["x0 = 0x1234;".to_string(), "foo();".to_string()]);
    }

    #[test]
    fn invert_cond_flips_operators() {
        assert_eq!(invert_cond("x21 == 0"), "x21 != 0");
        assert_eq!(invert_cond("w9 != 0x305"), "w9 == 0x305");
        assert_eq!(invert_cond("a < b"), "a >= b");
        assert_eq!(invert_cond("cond_ne"), "!(cond_ne)");
        assert!(!is_invertible("cond_ne"));
    }
}
