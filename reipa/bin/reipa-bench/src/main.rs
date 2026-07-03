use std::io::Write;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: reipa-bench <throughput|metadata> <binary> [--dump <csv>]";
    let mode = match args.get(1) {
        Some(m) => m.as_str(),
        None => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    let dump = args
        .iter()
        .position(|a| a == "--dump")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let emit = args
        .iter()
        .position(|a| a == "--emit")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let code = match mode {
        "throughput" => throughput(&path, dump.as_deref(), emit.as_deref()),
        "metadata" => metadata(&path),
        other => {
            eprintln!("unknown mode {other}\n{usage}");
            2
        }
    };
    std::process::exit(code);
}

fn load(path: &str) -> Result<(Vec<u8>, reipa_macho::MachOImage), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let image = reipa_macho::MachOImage::parse(&bytes).map_err(|e| e.to_string())?;
    Ok((bytes, image))
}

fn throughput(path: &str, dump: Option<&str>, emit: Option<&str>) -> i32 {
    let (bytes, image) = match load(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let slice = match reipa_macho::fat::select_arm64_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let sdata = slice.data;
    let text = match image.section_by_name("__text") {
        Some(t) => t,
        None => {
            eprintln!("no __text section");
            return 1;
        }
    };
    let off = text.offset as usize;
    let size = text.size as usize;
    let end = off.saturating_add(size).min(sdata.len());
    if off >= end {
        eprintln!(
            "__text out of range (off={off} size={size} slice={})",
            sdata.len()
        );
        return 1;
    }
    let code = &sdata[off..end];
    let n_words = code.len() / 4;
    let base = text.addr;

    let mut dumpf = dump.map(|p| {
        let f = std::fs::File::create(p).expect("create dump file");
        std::io::BufWriter::new(f)
    });
    let mut emitf = emit.map(|p| {
        let f = std::fs::File::create(p).expect("create emit file");
        std::io::BufWriter::new(f)
    });

    let start = Instant::now();
    let mut decoded: u64 = 0;
    let mut sink: u64 = 0;
    for i in 0..n_words {
        let b = i * 4;
        let word = u32::from_le_bytes([code[b], code[b + 1], code[b + 2], code[b + 3]]);
        let addr = base.wrapping_add(b as u64);
        let insn = reipa_arm64::decode(word, addr);
        sink = sink.wrapping_add(insn.text.len() as u64);
        decoded += 1;
        if let Some(f) = dumpf.as_mut() {
            let mnem = insn.text.split_whitespace().next().unwrap_or("");
            let _ = writeln!(f, "{addr:x},{word:08x},{mnem}");
        }
        if let Some(f) = emitf.as_mut() {
            let _ = writeln!(f, "{addr:x}: {word:08x}  {}", insn.text);
        }
    }
    if let Some(f) = dumpf.as_mut() {
        let _ = f.flush();
    }
    if let Some(f) = emitf.as_mut() {
        let _ = f.flush();
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let minsn_s = (decoded as f64 / secs) / 1.0e6;

    eprintln!(
        "decoded {decoded} insns of {} __text bytes in {:.1} ms  ({:.2} Minsn/s)  [checksum {sink}]",
        code.len(),
        secs * 1000.0,
        minsn_s
    );
    let ms = secs * 1000.0;
    let text_bytes = code.len();
    let bin = base_name(path);
    println!(
        "RESULT tool=reipa mode=throughput bin={bin} insns={decoded} text_bytes={text_bytes} ms={ms:.1} minsn_s={minsn_s:.2}"
    );
    0
}

fn metadata(path: &str) -> i32 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return 1;
        }
    };
    let start = Instant::now();
    let classes = match reipa_objc::parse_objc_classes(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let cats = reipa_objc::parse_objc_categories(&bytes).unwrap_or_default();
    let elapsed = start.elapsed();

    let n_classes = classes.len();
    let n_cats = cats.len();
    let mut n_methods = 0usize;
    let mut n_ivars = 0usize;
    let mut n_named_super = 0usize;
    for c in &classes {
        n_methods += c.instance_methods.len() + c.class_methods.len();
        n_ivars += c.ivars.len();
        if c.superclass.is_some() {
            n_named_super += 1;
        }
    }
    for c in &cats {
        n_methods += c.instance_methods.len() + c.class_methods.len();
    }
    let secs = elapsed.as_secs_f64();
    eprintln!(
        "recovered {n_classes} classes / {n_cats} categories / {n_methods} methods / {n_ivars} ivars in {:.1} ms",
        secs * 1000.0
    );
    println!(
        "RESULT tool=reipa mode=metadata bin={} classes={n_classes} categories={n_cats} methods={n_methods} ivars={n_ivars} named_super={n_named_super} ms={:.1}",
        base_name(path),
        secs * 1000.0
    );
    0
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}
