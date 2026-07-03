pub mod cfg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    Fallthrough,
    Branch(u64),
    Call(u64),
    CondBranch(u64),
    Return,
    Indirect,
    IndirectCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagKind {
    Cmp,
    Cmn,
    Tst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagOp {
    pub a: String,
    pub b: String,
    pub kind: FlagKind,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub raw: u32,
    pub text: String,
    pub flow: Flow,
    pub cond: Option<u8>,
    pub flags: Option<FlagOp>,
}

impl Insn {
    fn with_cond(mut self, c: u8) -> Insn {
        self.cond = Some(c);
        self
    }
    fn with_flags(mut self, a: String, b: String, kind: FlagKind) -> Insn {
        self.flags = Some(FlagOp { a, b, kind });
        self
    }
}

fn reg(n: u32, sf: bool, sp: bool) -> String {
    if n == 31 {
        if sp {
            "sp".to_string()
        } else if sf {
            "xzr".to_string()
        } else {
            "wzr".to_string()
        }
    } else {
        format!("{}{}", if sf { "x" } else { "w" }, n)
    }
}

fn sx(n: u32, sf: bool) -> String {
    reg(n, sf, false)
}

fn sext(v: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v as u64) << shift) as i64 >> shift
}

const COND: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

pub fn decode(raw: u32, addr: u64) -> Insn {
    let mk = |text: String, flow: Flow| Insn {
        addr,
        raw,
        text,
        flow,
        cond: None,
        flags: None,
    };
    let unk = || mk(format!(".word 0x{raw:08x}"), Flow::Fallthrough);

    if raw == 0xD503_201F {
        return mk("nop".to_string(), Flow::Fallthrough);
    }
    if raw & 0xFFFF_FC1F == 0xD65F_0000 {
        return mk("ret".to_string(), Flow::Return);
    }
    if raw & 0xFFFF_FC1F == 0xD61F_0000 {
        let rn = (raw >> 5) & 0x1f;
        return mk(format!("br {}", sx(rn, true)), Flow::Indirect);
    }
    if raw & 0xFFFF_FC1F == 0xD63F_0000 {
        let rn = (raw >> 5) & 0x1f;
        return mk(format!("blr {}", sx(rn, true)), Flow::IndirectCall);
    }
    if raw & 0x7C00_0000 == 0x1400_0000 {
        let imm = sext(raw & 0x03FF_FFFF, 26) << 2;
        let target = addr.wrapping_add(imm as u64);
        let link = raw & 0x8000_0000 != 0;
        let mn = if link { "bl" } else { "b" };
        let flow = if link {
            Flow::Call(target)
        } else {
            Flow::Branch(target)
        };
        return mk(format!("{mn} 0x{target:x}"), flow);
    }
    if raw & 0xFF00_0010 == 0x5400_0000 {
        let imm = sext((raw >> 5) & 0x7FFFF, 19) << 2;
        let target = addr.wrapping_add(imm as u64);
        let code = (raw & 0xf) as u8;
        let cond = COND[code as usize];
        return mk(format!("b.{cond} 0x{target:x}"), Flow::CondBranch(target)).with_cond(code);
    }
    if raw & 0x7E00_0000 == 0x3400_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let neg = raw & 0x0100_0000 != 0;
        let imm = sext((raw >> 5) & 0x7FFFF, 19) << 2;
        let target = addr.wrapping_add(imm as u64);
        let rt = raw & 0x1f;
        let mn = if neg { "cbnz" } else { "cbz" };
        return mk(
            format!("{mn} {}, 0x{target:x}", sx(rt, sf)),
            Flow::CondBranch(target),
        );
    }
    if raw & 0x7E00_0000 == 0x3600_0000 {
        let neg = raw & 0x0100_0000 != 0;
        let b5 = (raw >> 31) & 1;
        let b40 = (raw >> 19) & 0x1f;
        let bit = (b5 << 5) | b40;
        let imm = sext((raw >> 5) & 0x3FFF, 14) << 2;
        let target = addr.wrapping_add(imm as u64);
        let rt = raw & 0x1f;
        let sf = b5 == 1;
        let mn = if neg { "tbnz" } else { "tbz" };
        return mk(
            format!("{mn} {}, #{bit}, 0x{target:x}", sx(rt, sf)),
            Flow::CondBranch(target),
        );
    }
    if raw & 0xFFE0_001F == 0xD400_0001 {
        let imm = (raw >> 5) & 0xffff;
        return mk(format!("svc #0x{imm:x}"), Flow::Fallthrough);
    }

    if raw & 0x1F00_0000 == 0x1000_0000 {
        let op = raw & 0x8000_0000 != 0;
        let immlo = (raw >> 29) & 0x3;
        let immhi = (raw >> 5) & 0x7FFFF;
        let imm = (immhi << 2) | immlo;
        let rd = raw & 0x1f;
        if op {
            let base = addr & !0xFFF;
            let target = base.wrapping_add((sext(imm, 21) << 12) as u64);
            return mk(
                format!("adrp {}, 0x{target:x}", sx(rd, true)),
                Flow::Fallthrough,
            );
        } else {
            let target = addr.wrapping_add(sext(imm, 21) as u64);
            return mk(
                format!("adr {}, 0x{target:x}", sx(rd, true)),
                Flow::Fallthrough,
            );
        }
    }

    if raw & 0x1F80_0000 == 0x1280_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let opc = (raw >> 29) & 0x3;
        let hw = (raw >> 21) & 0x3;
        let imm16 = (raw >> 5) & 0xFFFF;
        let rd = raw & 0x1f;
        let shift = hw * 16;
        let lsl = if shift == 0 {
            String::new()
        } else {
            format!(", lsl #{shift}")
        };
        return match opc {
            0b00 => mk(
                format!("movn {}, #0x{imm16:x}{lsl}", sx(rd, sf)),
                Flow::Fallthrough,
            ),
            0b10 => {
                if shift == 0 {
                    mk(
                        format!("mov {}, #0x{imm16:x}", sx(rd, sf)),
                        Flow::Fallthrough,
                    )
                } else {
                    mk(
                        format!("movz {}, #0x{imm16:x}{lsl}", sx(rd, sf)),
                        Flow::Fallthrough,
                    )
                }
            }
            0b11 => mk(
                format!("movk {}, #0x{imm16:x}{lsl}", sx(rd, sf)),
                Flow::Fallthrough,
            ),
            _ => unk(),
        };
    }

    if raw & 0x1F00_0000 == 0x1100_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let sub = raw & 0x4000_0000 != 0;
        let set = raw & 0x2000_0000 != 0;
        let sh = raw & 0x0040_0000 != 0;
        let imm = (raw >> 10) & 0xFFF;
        let imm = if sh { imm << 12 } else { imm };
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        if set && rd == 31 {
            let mn = if sub { "cmp" } else { "cmn" };
            let kind = if sub { FlagKind::Cmp } else { FlagKind::Cmn };
            return mk(
                format!("{mn} {}, #0x{imm:x}", reg(rn, sf, true)),
                Flow::Fallthrough,
            )
            .with_flags(reg(rn, sf, true), format!("0x{imm:x}"), kind);
        }
        if !sub && !set && imm == 0 && (rd == 31 || rn == 31) {
            return mk(
                format!("mov {}, {}", reg(rd, sf, true), reg(rn, sf, true)),
                Flow::Fallthrough,
            );
        }
        let mn = match (sub, set) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        return mk(
            format!(
                "{mn} {}, {}, #0x{imm:x}",
                reg(rd, sf, !set),
                reg(rn, sf, true)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1F00_0000 == 0x0A00_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let opc = (raw >> 29) & 0x3;
        let n = raw & 0x0020_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let imm6 = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let shtype = (raw >> 22) & 0x3;
        if opc == 0b01 && !n && rn == 31 && imm6 == 0 {
            return mk(
                format!("mov {}, {}", sx(rd, sf), sx(rm, sf)),
                Flow::Fallthrough,
            );
        }
        let base = match opc {
            0b00 => "and",
            0b01 => "orr",
            0b10 => "eor",
            0b11 => "ands",
            _ => return unk(),
        };
        let mn = if n {
            match opc {
                0b00 => "bic",
                0b01 => "orn",
                0b10 => "eon",
                _ => "bics",
            }
        } else {
            base
        };
        if opc == 0b11 && !n && rd == 31 {
            return mk(
                format!("tst {}, {}", sx(rn, sf), sx(rm, sf)),
                Flow::Fallthrough,
            )
            .with_flags(sx(rn, sf), sx(rm, sf), FlagKind::Tst);
        }
        let sh = shift_str(shtype, imm6);
        return mk(
            format!("{mn} {}, {}, {}{}", sx(rd, sf), sx(rn, sf), sx(rm, sf), sh),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1F20_0000 == 0x0B00_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let sub = raw & 0x4000_0000 != 0;
        let set = raw & 0x2000_0000 != 0;
        let shtype = (raw >> 22) & 0x3;
        let rm = (raw >> 16) & 0x1f;
        let imm6 = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        if set && rd == 31 {
            let mn = if sub { "cmp" } else { "cmn" };
            let kind = if sub { FlagKind::Cmp } else { FlagKind::Cmn };
            let b = format!("{}{}", sx(rm, sf), shift_str(shtype, imm6));
            return mk(format!("{mn} {}, {b}", sx(rn, sf)), Flow::Fallthrough).with_flags(
                sx(rn, sf),
                b,
                kind,
            );
        }
        if sub && rn == 31 {
            let mn = if set { "negs" } else { "neg" };
            return mk(
                format!(
                    "{mn} {}, {}{}",
                    sx(rd, sf),
                    sx(rm, sf),
                    shift_str(shtype, imm6)
                ),
                Flow::Fallthrough,
            );
        }
        let mn = match (sub, set) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        return mk(
            format!(
                "{mn} {}, {}, {}{}",
                sx(rd, sf),
                sx(rn, sf),
                sx(rm, sf),
                shift_str(shtype, imm6)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x3F00_0000 == 0x3900_0000 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm12 = (raw >> 10) & 0xFFF;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        if size == 3 && opc == 2 {
            let off = imm12 << 3;
            let base = reg(rn, true, true);
            let mem = if off == 0 {
                format!("[{base}]")
            } else {
                format!("[{base}, #0x{off:x}]")
            };
            return mk(format!("prfm #0x{rt:x}, {mem}"), Flow::Fallthrough);
        }
        let (mn, sf, scale) = match (size, opc) {
            (0, 0) => ("strb", false, 0),
            (0, 1) => ("ldrb", false, 0),
            (0, 2) => ("ldrsb", true, 0),
            (0, 3) => ("ldrsb", false, 0),
            (1, 0) => ("strh", false, 1),
            (1, 1) => ("ldrh", false, 1),
            (1, 2) => ("ldrsh", true, 1),
            (1, 3) => ("ldrsh", false, 1),
            (2, 0) => ("str", false, 2),
            (2, 1) => ("ldr", false, 2),
            (2, 2) => ("ldrsw", true, 2),
            (3, 0) => ("str", true, 3),
            (3, 1) => ("ldr", true, 3),
            _ => return unk(),
        };
        let off = imm12 << scale;
        let base = reg(rn, true, true);
        let mem = if off == 0 {
            format!("[{base}]")
        } else {
            format!("[{base}, #0x{off:x}]")
        };
        return mk(format!("{mn} {}, {mem}", sx(rt, sf)), Flow::Fallthrough);
    }

    if raw & 0x3B00_0000 == 0x1800_0000 {
        let opc = (raw >> 30) & 0x3;
        let sf = opc == 1;
        let imm = sext((raw >> 5) & 0x7FFFF, 19) << 2;
        let target = addr.wrapping_add(imm as u64);
        let rt = raw & 0x1f;
        return mk(
            format!("ldr {}, 0x{target:x}", sx(rt, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1FE0_0000 == 0x1A80_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let op = raw & 0x4000_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let cond = (raw >> 12) & 0xf;
        let op2 = (raw >> 10) & 0x3;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let cc = COND[cond as usize];
        if !op && op2 == 1 && rn == 31 && rm == 31 && cond < 0b1110 {
            let inv = COND[(cond ^ 1) as usize];
            return mk(format!("cset {}, {inv}", sx(rd, sf)), Flow::Fallthrough);
        }
        let mn = match (op, op2) {
            (false, 0) => "csel",
            (false, 1) => "csinc",
            (true, 0) => "csinv",
            (true, 1) => "csneg",
            _ => return unk(),
        };
        return mk(
            format!("{mn} {}, {}, {}, {cc}", sx(rd, sf), sx(rn, sf), sx(rm, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1F00_0000 == 0x1B00_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let o0 = raw & 0x0000_8000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let ra = (raw >> 10) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let op31 = (raw >> 21) & 0x7;
        if op31 == 0 {
            if ra == 31 {
                let mn = if o0 { "mneg" } else { "mul" };
                return mk(
                    format!("{mn} {}, {}, {}", sx(rd, sf), sx(rn, sf), sx(rm, sf)),
                    Flow::Fallthrough,
                );
            }
            let mn = if o0 { "msub" } else { "madd" };
            return mk(
                format!(
                    "{mn} {}, {}, {}, {}",
                    sx(rd, sf),
                    sx(rn, sf),
                    sx(rm, sf),
                    sx(ra, sf)
                ),
                Flow::Fallthrough,
            );
        }
        let mn = match (op31, o0) {
            (0b001, false) => "smaddl",
            (0b001, true) => "smsubl",
            (0b101, false) => "umaddl",
            (0b101, true) => "umsubl",
            (0b010, false) => "smulh",
            (0b110, false) => "umulh",
            _ => return unk(),
        };
        if mn == "smulh" || mn == "umulh" {
            return mk(
                format!("{mn} {}, {}, {}", sx(rd, true), sx(rn, true), sx(rm, true)),
                Flow::Fallthrough,
            );
        }
        if ra == 31 && (mn == "smaddl" || mn == "umaddl") {
            let alias = if mn == "smaddl" { "smull" } else { "umull" };
            return mk(
                format!(
                    "{alias} {}, {}, {}",
                    sx(rd, true),
                    sx(rn, false),
                    sx(rm, false)
                ),
                Flow::Fallthrough,
            );
        }
        return mk(
            format!(
                "{mn} {}, {}, {}, {}",
                sx(rd, true),
                sx(rn, false),
                sx(rm, false),
                sx(ra, true)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x7FE0_0000 == 0x1AC0_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let opc = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match opc {
            0b000010 => "udiv",
            0b000011 => "sdiv",
            0b001000 => "lsl",
            0b001001 => "lsr",
            0b001010 => "asr",
            0b001011 => "ror",
            _ => return unk(),
        };
        return mk(
            format!("{mn} {}, {}, {}", sx(rd, sf), sx(rn, sf), sx(rm, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1F80_0000 == 0x1300_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let opc = (raw >> 29) & 0x3;
        let immr = (raw >> 16) & 0x3f;
        let imms = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let width = if sf { 64 } else { 32 };
        if opc == 0b10 {
            if imms != width - 1 && imms + 1 == immr {
                let sh = width - immr;
                return mk(
                    format!("lsl {}, {}, #{sh}", sx(rd, sf), sx(rn, sf)),
                    Flow::Fallthrough,
                );
            }
            if imms == width - 1 {
                return mk(
                    format!("lsr {}, {}, #{immr}", sx(rd, sf), sx(rn, sf)),
                    Flow::Fallthrough,
                );
            }
            if immr == 0 && imms == 7 {
                return mk(
                    format!("uxtb {}, {}", sx(rd, false), sx(rn, false)),
                    Flow::Fallthrough,
                );
            }
            if immr == 0 && imms == 15 {
                return mk(
                    format!("uxth {}, {}", sx(rd, false), sx(rn, false)),
                    Flow::Fallthrough,
                );
            }
            let w = imms.wrapping_sub(immr).wrapping_add(1);
            return mk(
                format!("ubfx {}, {}, #{immr}, #{w}", sx(rd, sf), sx(rn, sf)),
                Flow::Fallthrough,
            );
        }
        if opc == 0b00 {
            if imms == width - 1 {
                return mk(
                    format!("asr {}, {}, #{immr}", sx(rd, sf), sx(rn, sf)),
                    Flow::Fallthrough,
                );
            }
            if immr == 0 && imms == 7 {
                return mk(
                    format!("sxtb {}, {}", sx(rd, sf), sx(rn, false)),
                    Flow::Fallthrough,
                );
            }
            if immr == 0 && imms == 15 {
                return mk(
                    format!("sxth {}, {}", sx(rd, sf), sx(rn, false)),
                    Flow::Fallthrough,
                );
            }
            if immr == 0 && imms == 31 && sf {
                return mk(
                    format!("sxtw {}, {}", sx(rd, true), sx(rn, false)),
                    Flow::Fallthrough,
                );
            }
            let w = imms.wrapping_sub(immr).wrapping_add(1);
            return mk(
                format!("sbfx {}, {}, #{immr}, #{w}", sx(rd, sf), sx(rn, sf)),
                Flow::Fallthrough,
            );
        }
        return mk(
            format!("bfm {}, {}, #{immr}, #{imms}", sx(rd, sf), sx(rn, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x3F00_0000 == 0x3800_0000 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm9 = sext((raw >> 12) & 0x1ff, 9);
        let idx = (raw >> 10) & 0x3;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let (base_mn, sf) = match (size, opc) {
            (0, 0) => ("strb", false),
            (0, 1) => ("ldrb", false),
            (0, 2) => ("ldrsb", true),
            (0, 3) => ("ldrsb", false),
            (1, 0) => ("strh", false),
            (1, 1) => ("ldrh", false),
            (1, 2) => ("ldrsh", true),
            (1, 3) => ("ldrsh", false),
            (2, 0) => ("str", false),
            (2, 1) => ("ldr", false),
            (2, 2) => ("ldrsw", true),
            (3, 0) => ("str", true),
            (3, 1) => ("ldr", true),
            _ => return unk(),
        };
        let mn = if idx == 0 {
            match base_mn {
                "str" => "stur",
                "ldr" => "ldur",
                "strb" => "sturb",
                "ldrb" => "ldurb",
                "strh" => "sturh",
                "ldrh" => "ldurh",
                "ldrsb" => "ldursb",
                "ldrsh" => "ldursh",
                "ldrsw" => "ldursw",
                other => other,
            }
        } else {
            base_mn
        };
        let base = reg(rn, true, true);
        let off = simm(imm9);
        let mem = match idx {
            0b01 => format!("[{base}], #{off}"),
            0b11 => format!("[{base}, #{off}]!"),
            _ if imm9 == 0 => format!("[{base}]"),
            _ => format!("[{base}, #{off}]"),
        };
        return mk(format!("{mn} {}, {mem}", sx(rt, sf)), Flow::Fallthrough);
    }

    if raw & 0x3E00_0000 == 0x2800_0000 {
        let opc = (raw >> 30) & 0x3;
        let load = raw & 0x0040_0000 != 0;
        let imm7 = (raw >> 15) & 0x7f;
        let rt2 = (raw >> 10) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let ldpsw = opc == 1 && load;
        let sf = opc == 2 || ldpsw;
        let scale = if opc == 2 { 3 } else { 2 };
        let off = sext(imm7, 7) << scale;
        let mn = if ldpsw {
            "ldpsw"
        } else if load {
            "ldp"
        } else {
            "stp"
        };
        let base = reg(rn, true, true);
        let mem = if off == 0 {
            format!("[{base}]")
        } else {
            format!("[{base}, #{}]", simm(off))
        };
        return mk(
            format!("{mn} {}, {}, {mem}", sx(rt, sf), sx(rt2, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1F80_0000 == 0x1200_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let opc = (raw >> 29) & 0x3;
        let n = (raw >> 22) & 1;
        let immr = (raw >> 16) & 0x3f;
        let imms = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let datasize = if sf { 64 } else { 32 };
        if !sf && n == 1 {
            return unk();
        }
        let imm = match decode_bitmask(n, imms, immr, datasize) {
            Some(v) => v,
            None => return unk(),
        };
        if opc == 0b01 && rn == 31 {
            return mk(
                format!("mov {}, #0x{imm:x}", reg(rd, sf, true)),
                Flow::Fallthrough,
            );
        }
        if opc == 0b11 && rd == 31 {
            return mk(format!("tst {}, #0x{imm:x}", sx(rn, sf)), Flow::Fallthrough);
        }
        let mn = match opc {
            0b00 => "and",
            0b01 => "orr",
            0b10 => "eor",
            _ => "ands",
        };
        let rd_s = reg(rd, sf, opc != 0b11);
        return mk(
            format!("{mn} {rd_s}, {}, #0x{imm:x}", sx(rn, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1FE0_0000 == 0x0B20_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let sub = raw & 0x4000_0000 != 0;
        let set = raw & 0x2000_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let option = (raw >> 13) & 0x7;
        let imm3 = (raw >> 10) & 0x7;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let ext = [
            "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
        ][option as usize];
        let rm_x = option == 0b011 || option == 0b111;
        let extstr = if imm3 == 0 {
            format!(", {ext}")
        } else {
            format!(", {ext} #{imm3}")
        };
        if set && rd == 31 {
            let mn = if sub { "cmp" } else { "cmn" };
            let kind = if sub { FlagKind::Cmp } else { FlagKind::Cmn };
            let b = format!("{}{extstr}", sx(rm, rm_x));
            return mk(
                format!("{mn} {}, {b}", reg(rn, sf, true)),
                Flow::Fallthrough,
            )
            .with_flags(reg(rn, sf, true), b, kind);
        }
        let mn = match (sub, set) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        return mk(
            format!(
                "{mn} {}, {}, {}{extstr}",
                reg(rd, sf, !set),
                reg(rn, sf, true),
                sx(rm, rm_x)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x3FE0_0000 == 0x3A40_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let op = raw & 0x4000_0000 != 0;
        let imm_form = (raw >> 11) & 1 == 1;
        let rm_or_imm = (raw >> 16) & 0x1f;
        let cond = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let nzcv = raw & 0xf;
        let mn = if op { "ccmp" } else { "ccmn" };
        let b = if imm_form {
            format!("#0x{rm_or_imm:x}")
        } else {
            sx(rm_or_imm, sf)
        };
        return mk(
            format!(
                "{mn} {}, {b}, #0x{nzcv:x}, {}",
                sx(rn, sf),
                COND[cond as usize]
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x7FE0_0000 == 0x5AC0_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let opcode = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match opcode {
            0b000000 => "rbit",
            0b000001 => "rev16",
            0b000010 => {
                if sf {
                    "rev32"
                } else {
                    "rev"
                }
            }
            0b000011 => "rev",
            0b000100 => "clz",
            0b000101 => "cls",
            _ => return unk(),
        };
        return mk(
            format!("{mn} {}, {}", sx(rd, sf), sx(rn, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF00_0000 == 0xD400_0000 {
        let opc = (raw >> 21) & 0x7;
        let ll = raw & 0x3;
        let imm = (raw >> 5) & 0xffff;
        let mn = match (opc, ll) {
            (0b001, 0b00) => "brk",
            (0b010, 0b00) => "hlt",
            (0b101, 0b01) => "dcps1",
            (0b101, 0b10) => "dcps2",
            (0b101, 0b11) => "dcps3",
            _ => return unk(),
        };
        return mk(format!("{mn} #0x{imm:x}"), Flow::Fallthrough);
    }

    if raw & 0xFFFF_0000 == 0x0000_0000 {
        return mk(format!("udf #0x{:x}", raw & 0xffff), Flow::Fallthrough);
    }

    if raw & 0x3F00_0000 == 0x0800_0000 {
        let size = (raw >> 30) & 0x3;
        let o2 = (raw >> 23) & 1;
        let l = (raw >> 22) & 1;
        let o1 = (raw >> 21) & 1;
        let rs = (raw >> 16) & 0x1f;
        let o0 = (raw >> 15) & 1;
        let rt2 = (raw >> 10) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let suf = match size {
            0 => "b",
            1 => "h",
            _ => "",
        };
        let sf = size == 3;
        let base = reg(rn, true, true);
        if o1 == 1 {
            let mn = match (l, o0) {
                (0, 0) => "stxp",
                (0, 1) => "stlxp",
                (1, 0) => "ldxp",
                _ => "ldaxp",
            };
            if l == 0 {
                return mk(
                    format!(
                        "{mn} {}, {}, {}, [{base}]",
                        reg(rs, false, false),
                        sx(rt, sf),
                        sx(rt2, sf)
                    ),
                    Flow::Fallthrough,
                );
            }
            return mk(
                format!("{mn} {}, {}, [{base}]", sx(rt, sf), sx(rt2, sf)),
                Flow::Fallthrough,
            );
        }
        if o2 == 0 {
            let mn = match (l, o0) {
                (0, 0) => format!("stxr{suf}"),
                (0, 1) => format!("stlxr{suf}"),
                (1, 0) => format!("ldxr{suf}"),
                _ => format!("ldaxr{suf}"),
            };
            if l == 0 {
                return mk(
                    format!("{mn} {}, {}, [{base}]", reg(rs, false, false), sx(rt, sf),),
                    Flow::Fallthrough,
                );
            }
            return mk(format!("{mn} {}, [{base}]", sx(rt, sf)), Flow::Fallthrough);
        }
        let mn = match (l, o0) {
            (0, 0) => format!("stllr{suf}"),
            (0, 1) => format!("stlr{suf}"),
            (1, 0) => format!("ldlar{suf}"),
            _ => format!("ldar{suf}"),
        };
        return mk(format!("{mn} {}, [{base}]", sx(rt, sf)), Flow::Fallthrough);
    }

    if raw & 0x3F00_0000 == 0x3D00_0000 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm12 = (raw >> 10) & 0xFFF;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let (letter, scale) = simd_ls_size(size, opc);
        let load = (opc & 1) == 1;
        let mn = if load { "ldr" } else { "str" };
        let off = imm12 << scale;
        let base = reg(rn, true, true);
        let mem = if off == 0 {
            format!("[{base}]")
        } else {
            format!("[{base}, #0x{off:x}]")
        };
        return mk(format!("{mn} {letter}{rt}, {mem}"), Flow::Fallthrough);
    }

    if raw & 0x3F00_0000 == 0x3C00_0000 {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm9 = sext((raw >> 12) & 0x1ff, 9);
        let idx = (raw >> 10) & 0x3;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let (letter, _scale) = simd_ls_size(size, opc);
        let load = (opc & 1) == 1;
        let mn = if idx == 0 {
            if load {
                "ldur"
            } else {
                "stur"
            }
        } else if load {
            "ldr"
        } else {
            "str"
        };
        let base = reg(rn, true, true);
        let off = simm(imm9);
        let mem = match idx {
            0b01 => format!("[{base}], #{off}"),
            0b11 => format!("[{base}, #{off}]!"),
            _ if imm9 == 0 => format!("[{base}]"),
            _ => format!("[{base}, #{off}]"),
        };
        return mk(format!("{mn} {letter}{rt}, {mem}"), Flow::Fallthrough);
    }

    if raw & 0x3E00_0000 == 0x2C00_0000 {
        let opc = (raw >> 30) & 0x3;
        let load = raw & 0x0040_0000 != 0;
        let imm7 = (raw >> 15) & 0x7f;
        let rt2 = (raw >> 10) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let (letter, scale) = match opc {
            0 => ('s', 2),
            1 => ('d', 3),
            _ => ('q', 4),
        };
        let off = sext(imm7, 7) << scale;
        let mn = if load { "ldp" } else { "stp" };
        let base = reg(rn, true, true);
        let mem = if off == 0 {
            format!("[{base}]")
        } else {
            format!("[{base}, #{}]", simm(off))
        };
        return mk(
            format!("{mn} {letter}{rt}, {letter}{rt2}, {mem}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_FC00 == 0x1E20_2000 {
        let ftype = (raw >> 22) & 0x3;
        let rm = (raw >> 16) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let opcode2 = raw & 0x1f;
        let e = opcode2 & 0x10 != 0;
        let zero = opcode2 & 0x08 != 0;
        let mn = if e { "fcmpe" } else { "fcmp" };
        if zero {
            return mk(
                format!("{mn} {}, #0.0", fp_reg(ftype, rn)),
                Flow::Fallthrough,
            );
        }
        return mk(
            format!("{mn} {}, {}", fp_reg(ftype, rn), fp_reg(ftype, rm)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_7C00 == 0x1E20_4000 {
        let ftype = (raw >> 22) & 0x3;
        let opcode = (raw >> 15) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match opcode {
            0b000000 => "fmov",
            0b000001 => "fabs",
            0b000010 => "fneg",
            0b000011 => "fsqrt",
            0b000100 | 0b000101 | 0b000111 => "fcvt",
            0b001000 => "frintn",
            0b001001 => "frintp",
            0b001010 => "frintm",
            0b001011 => "frintz",
            0b001100 => "frinta",
            0b001110 => "frintx",
            0b001111 => "frinti",
            _ => return unk(),
        };
        return mk(
            format!("{mn} {}, {}", fp_reg(ftype, rd), fp_reg(ftype, rn)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_0C00 == 0x1E20_0800 {
        let ftype = (raw >> 22) & 0x3;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match opcode {
            0 => "fmul",
            1 => "fdiv",
            2 => "fadd",
            3 => "fsub",
            4 => "fmax",
            5 => "fmin",
            6 => "fmaxnm",
            7 => "fminnm",
            8 => "fnmul",
            _ => return unk(),
        };
        return mk(
            format!(
                "{mn} {}, {}, {}",
                fp_reg(ftype, rd),
                fp_reg(ftype, rn),
                fp_reg(ftype, rm)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_0C00 == 0x1E20_0C00 {
        let ftype = (raw >> 22) & 0x3;
        let rm = (raw >> 16) & 0x1f;
        let cond = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        return mk(
            format!(
                "fcsel {}, {}, {}, {}",
                fp_reg(ftype, rd),
                fp_reg(ftype, rn),
                fp_reg(ftype, rm),
                COND[cond as usize]
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_0C00 == 0x1E20_0400 {
        let ftype = (raw >> 22) & 0x3;
        let rm = (raw >> 16) & 0x1f;
        let cond = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let e = raw & 0x10 != 0;
        let nzcv = raw & 0xf;
        let mn = if e { "fccmpe" } else { "fccmp" };
        return mk(
            format!(
                "{mn} {}, {}, #0x{nzcv:x}, {}",
                fp_reg(ftype, rn),
                fp_reg(ftype, rm),
                COND[cond as usize]
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFF20_1FE0 == 0x1E20_1000 {
        let ftype = (raw >> 22) & 0x3;
        let imm8 = (raw >> 13) & 0xff;
        let rd = raw & 0x1f;
        let val = vfp_expand_imm(imm8);
        return mk(
            format!("fmov {}, #{val:.8}", fp_reg(ftype, rd)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x7F20_FC00 == 0x1E20_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let ftype = (raw >> 22) & 0x3;
        let rmode = (raw >> 19) & 0x3;
        let opcode = (raw >> 16) & 0x7;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (rmode, opcode) {
            (0, 0b010) => "scvtf",
            (0, 0b011) => "ucvtf",
            (0, 0b000) => "fcvtns",
            (0, 0b001) => "fcvtnu",
            (1, 0b000) => "fcvtps",
            (1, 0b001) => "fcvtpu",
            (2, 0b000) => "fcvtms",
            (2, 0b001) => "fcvtmu",
            (3, 0b000) => "fcvtzs",
            (3, 0b001) => "fcvtzu",
            (0, 0b100) => "fcvtas",
            (0, 0b101) => "fcvtau",
            (0, 0b110) => "fmov",
            (0, 0b111) => "fmov",
            _ => return unk(),
        };
        let (int_to_fp, fp_to_int) = match opcode {
            0b010 | 0b011 | 0b111 => (true, false),
            0b110 => (false, true),
            _ => (false, true),
        };
        if int_to_fp {
            return mk(
                format!("{mn} {}, {}", fp_reg(ftype, rd), sx(rn, sf)),
                Flow::Fallthrough,
            );
        }
        if fp_to_int {
            return mk(
                format!("{mn} {}, {}", sx(rd, sf), fp_reg(ftype, rn)),
                Flow::Fallthrough,
            );
        }
        return unk();
    }

    if raw & 0xFF00_0000 == 0x1F00_0000 {
        let ftype = (raw >> 22) & 0x3;
        let o1 = (raw >> 21) & 1;
        let rm = (raw >> 16) & 0x1f;
        let o0 = (raw >> 15) & 1;
        let ra = (raw >> 10) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (o1, o0) {
            (0, 0) => "fmadd",
            (0, 1) => "fmsub",
            (1, 0) => "fnmadd",
            _ => "fnmsub",
        };
        return mk(
            format!(
                "{mn} {}, {}, {}, {}",
                fp_reg(ftype, rd),
                fp_reg(ftype, rn),
                fp_reg(ftype, rm),
                fp_reg(ftype, ra)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x7FA0_0000 == 0x1380_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let imms = (raw >> 10) & 0x3f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        if rn == rm {
            return mk(
                format!("ror {}, {}, #0x{imms:x}", sx(rd, sf), sx(rn, sf)),
                Flow::Fallthrough,
            );
        }
        return mk(
            format!(
                "extr {}, {}, {}, #0x{imms:x}",
                sx(rd, sf),
                sx(rn, sf),
                sx(rm, sf)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0x1FE0_FC00 == 0x1A00_0000 {
        let sf = raw & 0x8000_0000 != 0;
        let sub = raw & 0x4000_0000 != 0;
        let set = raw & 0x2000_0000 != 0;
        let rm = (raw >> 16) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        if sub && rn == 31 {
            let mn = if set { "ngcs" } else { "ngc" };
            return mk(
                format!("{mn} {}, {}", sx(rd, sf), sx(rm, sf)),
                Flow::Fallthrough,
            );
        }
        let mn = match (sub, set) {
            (false, false) => "adc",
            (false, true) => "adcs",
            (true, false) => "sbc",
            (true, true) => "sbcs",
        };
        return mk(
            format!("{mn} {}, {}, {}", sx(rd, sf), sx(rn, sf), sx(rm, sf)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x9F20_0400 == 0x0E20_0400 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let hi = (raw >> 23) & 1;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 11) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        if u == 0 && opcode == 0x03 && size == 2 && rm == rn {
            let a = varr(0, q);
            return mk(format!("mov v{rd}.{a}, v{rn}.{a}"), Flow::Fallthrough);
        }
        let mn = match (u, opcode) {
            (0, 0x03) => ["and", "bic", "orr", "orn"][size as usize],
            (1, 0x03) => ["eor", "bsl", "bit", "bif"][size as usize],
            (0, 0x10) => "add",
            (1, 0x10) => "sub",
            (0, 0x11) => "cmtst",
            (1, 0x11) => "cmeq",
            (0, 0x06) => "cmgt",
            (1, 0x06) => "cmhi",
            (0, 0x07) => "cmge",
            (1, 0x07) => "cmhs",
            (0, 0x13) => "mul",
            (1, 0x13) => "pmul",
            (0, 0x0c) => "smax",
            (1, 0x0c) => "umax",
            (0, 0x0d) => "smin",
            (1, 0x0d) => "umin",
            (0, 0x01) => "sqadd",
            (1, 0x01) => "uqadd",
            (0, 0x0e) => "sabd",
            (1, 0x0e) => "uabd",
            (0, 0x08) => "sshl",
            (1, 0x08) => "ushl",
            (0, 0x12) => "mla",
            (1, 0x12) => "mls",
            (0, 0x18) => {
                if hi == 0 {
                    "fmaxnm"
                } else {
                    "fminnm"
                }
            }
            (0, 0x19) => {
                if hi == 0 {
                    "fmla"
                } else {
                    "fmls"
                }
            }
            (0, 0x1a) => {
                if hi == 0 {
                    "fadd"
                } else {
                    "fsub"
                }
            }
            (0, 0x1b) => "fmulx",
            (0, 0x1c) => "fcmeq",
            (0, 0x1e) => {
                if hi == 0 {
                    "fmax"
                } else {
                    "fmin"
                }
            }
            (0, 0x1f) => {
                if hi == 0 {
                    "frecps"
                } else {
                    "frsqrts"
                }
            }
            (1, 0x18) => {
                if hi == 0 {
                    "fmaxnmp"
                } else {
                    "fminnmp"
                }
            }
            (1, 0x1a) => {
                if hi == 0 {
                    "faddp"
                } else {
                    "fabd"
                }
            }
            (1, 0x1b) => "fmul",
            (1, 0x1c) => {
                if hi == 0 {
                    "fcmge"
                } else {
                    "fcmgt"
                }
            }
            (1, 0x1d) => {
                if hi == 0 {
                    "facge"
                } else {
                    "facgt"
                }
            }
            (1, 0x1e) => {
                if hi == 0 {
                    "fmaxp"
                } else {
                    "fminp"
                }
            }
            (1, 0x1f) => "fdiv",
            _ => return unk(),
        };
        let arr = if opcode >= 0x18 {
            farr(hi, q)
        } else {
            varr(size, q)
        };
        return mk(
            format!("{mn} v{rd}.{arr}, v{rn}.{arr}, v{rm}.{arr}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0x9FE0_0400 == 0x0E00_0400 {
        let q = (raw >> 30) & 1;
        let op = (raw >> 29) & 1;
        let imm5 = (raw >> 16) & 0x1f;
        let imm4 = (raw >> 11) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let size = imm5.trailing_zeros().min(3);
        let arr = varr(size, q);
        if op == 1 {
            return mk(
                format!("mov v{rd}.{arr}[?], v{rn}.{arr}[?]"),
                Flow::Fallthrough,
            );
        }
        return match imm4 {
            0b0000 => mk(
                format!("dup v{rd}.{arr}, v{rn}.{arr}[?]"),
                Flow::Fallthrough,
            ),
            0b0001 => {
                let gp = size == 3;
                mk(
                    format!("dup v{rd}.{arr}, {}", sx(rn, gp)),
                    Flow::Fallthrough,
                )
            }
            0b0011 => mk(
                format!("mov v{rd}.{arr}[?], {}", sx(rn, size == 3)),
                Flow::Fallthrough,
            ),
            0b0101 => mk(
                format!("smov {}, v{rn}.{arr}[?]", sx(rd, q == 1)),
                Flow::Fallthrough,
            ),
            0b0111 => {
                let mn = if size >= 2 { "mov" } else { "umov" };
                mk(
                    format!("{mn} {}, v{rn}.{arr}[?]", sx(rd, q == 1)),
                    Flow::Fallthrough,
                )
            }
            _ => unk(),
        };
    }

    if raw & 0xBF20_8C00 == 0x0E00_0800 {
        let q = (raw >> 30) & 1;
        let size = (raw >> 22) & 3;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 12) & 0x7;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match opcode {
            0b001 => "uzp1",
            0b010 => "trn1",
            0b011 => "zip1",
            0b101 => "uzp2",
            0b110 => "trn2",
            0b111 => "zip2",
            _ => return unk(),
        };
        let a = varr(size, q);
        return mk(
            format!("{mn} v{rd}.{a}, v{rn}.{a}, v{rm}.{a}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0xBF20_9C00 == 0x0E00_0000 {
        let q = (raw >> 30) & 1;
        let rm = (raw >> 16) & 0x1f;
        let op = (raw >> 12) & 1;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = if op == 1 { "tbx" } else { "tbl" };
        let a = varr(0, q);
        return mk(
            format!("{mn} v{rd}.{a}, {{v{rn}.16b}}, v{rm}.{a}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0x9F3E_0C00 == 0x0E30_0800 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let opcode = (raw >> 12) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x03) => "saddlv",
            (1, 0x03) => "uaddlv",
            (0, 0x0a) => "smaxv",
            (1, 0x0a) => "umaxv",
            (0, 0x1a) => "sminv",
            (1, 0x1a) => "uminv",
            (_, 0x1b) => "addv",
            (1, 0x0c) => "fmaxnmv",
            (1, 0x0f) => "fmaxv",
            (1, 0x2c) => "fminnmv",
            _ => return unk(),
        };
        return mk(
            format!("{mn} v{rd}, v{rn}.{}", varr(size, q)),
            Flow::Fallthrough,
        );
    }

    if raw & 0x9F3E_0C00 == 0x0E20_0800 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let hi = (raw >> 23) & 1;
        let opcode = (raw >> 12) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x00) => "rev64",
            (1, 0x00) => "rev32",
            (0, 0x01) => "rev16",
            (0, 0x04) => "cls",
            (1, 0x04) => "clz",
            (0, 0x05) => "cnt",
            (1, 0x05) => {
                if size == 1 {
                    "rbit"
                } else {
                    "mvn"
                }
            }
            (0, 0x06) => "sadalp",
            (1, 0x06) => "uadalp",
            (0, 0x0b) => "abs",
            (1, 0x0b) => "neg",
            (0, 0x08) => "cmgt",
            (1, 0x08) => "cmge",
            (0, 0x09) => "cmeq",
            (1, 0x09) => "cmle",
            (0, 0x0a) => "cmlt",
            (0, 0x12) => "xtn",
            (1, 0x12) => "sqxtun",
            (0, 0x14) => "sqxtn",
            (1, 0x14) => "uqxtn",
            (0, 0x13) => "shll",
            (0, 0x0c) => "fcmgt",
            (1, 0x0c) => "fcmge",
            (0, 0x0d) => "fcmeq",
            (1, 0x0d) => "fcmle",
            (0, 0x0e) => "fcmlt",
            (0, 0x0f) => "fabs",
            (1, 0x0f) => "fneg",
            (0, 0x16) => "fcvtn",
            (0, 0x17) => "fcvtl",
            (0, 0x1a) => {
                if hi == 1 {
                    "fcvtps"
                } else {
                    "fcvtns"
                }
            }
            (1, 0x1a) => {
                if hi == 1 {
                    "fcvtpu"
                } else {
                    "fcvtnu"
                }
            }
            (0, 0x1b) => {
                if hi == 1 {
                    "fcvtzs"
                } else {
                    "fcvtms"
                }
            }
            (1, 0x1b) => {
                if hi == 1 {
                    "fcvtzu"
                } else {
                    "fcvtmu"
                }
            }
            (0, 0x1d) => {
                if hi == 1 {
                    "frecpe"
                } else {
                    "scvtf"
                }
            }
            (1, 0x1d) => {
                if hi == 1 {
                    "frsqrte"
                } else {
                    "ucvtf"
                }
            }
            (1, 0x1f) => "fsqrt",
            (0, 0x18) => {
                if hi == 1 {
                    "frintp"
                } else {
                    "frintn"
                }
            }
            (0, 0x19) => {
                if hi == 1 {
                    "frintz"
                } else {
                    "frintm"
                }
            }
            _ => return unk(),
        };
        let two = q == 1 && matches!(opcode, 0x12 | 0x13 | 0x14 | 0x16 | 0x17);
        let mn = if two {
            match mn {
                "xtn" => "xtn2",
                "sqxtun" => "sqxtun2",
                "sqxtn" => "sqxtn2",
                "uqxtn" => "uqxtn2",
                "shll" => "shll2",
                "fcvtn" => "fcvtn2",
                "fcvtl" => "fcvtl2",
                other => other,
            }
        } else {
            mn
        };
        let arr = if (0x0c..=0x1f).contains(&opcode) {
            farr(hi, q)
        } else {
            varr(size, q)
        };
        let is_cmp0 = (0x08..=0x0a).contains(&opcode) || (0x0c..=0x0e).contains(&opcode);
        if is_cmp0 {
            let zero = if opcode >= 0x0c { ", #0.0" } else { ", #0" };
            return mk(
                format!("{mn} v{rd}.{arr}, v{rn}.{arr}{zero}"),
                Flow::Fallthrough,
            );
        }
        return mk(format!("{mn} v{rd}.{arr}, v{rn}.{arr}"), Flow::Fallthrough);
    }

    if raw & 0xBF20_8400 == 0x2E00_0000 {
        let q = (raw >> 30) & 1;
        let rm = (raw >> 16) & 0x1f;
        let imm4 = (raw >> 11) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let a = varr(0, q);
        return mk(
            format!("ext v{rd}.{a}, v{rn}.{a}, v{rm}.{a}, #{imm4}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0xBF00_0000 == 0x0C00_0000 {
        let q = (raw >> 30) & 1;
        let post = (raw >> 23) & 1;
        let l = (raw >> 22) & 1;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 12) & 0xf;
        let size = (raw >> 10) & 3;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let (stem, regs) = match opcode {
            0b0000 => ("4", 4),
            0b0010 => ("1", 4),
            0b0100 => ("3", 3),
            0b0110 => ("1", 3),
            0b0111 => ("1", 1),
            0b1000 => ("2", 2),
            0b1010 => ("1", 2),
            _ => return unk(),
        };
        let mn = if l == 1 {
            format!("ld{stem}")
        } else {
            format!("st{stem}")
        };
        let a = varr(size, q);
        let list = (0..regs)
            .map(|i| format!("v{}.{a}", (rt + i) & 0x1f))
            .collect::<Vec<_>>()
            .join(", ");
        let base = reg(rn, true, true);
        let mem = if post == 0 {
            format!("[{base}]")
        } else if rm == 31 {
            let bytes = regs * if q == 1 { 16 } else { 8 };
            format!("[{base}], #{bytes}")
        } else {
            format!("[{base}], {}", sx(rm, true))
        };
        return mk(format!("{mn} {{{list}}}, {mem}"), Flow::Fallthrough);
    }

    if raw & 0xFFFF_F0FF == 0xD503_305F {
        let crm = (raw >> 8) & 0xf;
        if crm == 0xf {
            return mk("clrex".to_string(), Flow::Fallthrough);
        }
        return mk(format!("clrex #0x{crm:x}"), Flow::Fallthrough);
    }

    if raw & 0x9F20_0C00 == 0x0E20_0000 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x0) => "saddl",
            (1, 0x0) => "uaddl",
            (0, 0x1) => "saddw",
            (1, 0x1) => "uaddw",
            (0, 0x2) => "ssubl",
            (1, 0x2) => "usubl",
            (0, 0x3) => "ssubw",
            (1, 0x3) => "usubw",
            (0, 0x4) => "addhn",
            (1, 0x4) => "raddhn",
            (0, 0x5) => "sabal",
            (1, 0x5) => "uabal",
            (0, 0x6) => "subhn",
            (1, 0x6) => "rsubhn",
            (0, 0x7) => "sabdl",
            (1, 0x7) => "uabdl",
            (0, 0x8) => "smlal",
            (1, 0x8) => "umlal",
            (0, 0x9) => "sqdmlal",
            (0, 0xa) => "smlsl",
            (1, 0xa) => "umlsl",
            (0, 0xb) => "sqdmlsl",
            (0, 0xc) => "smull",
            (1, 0xc) => "umull",
            (0, 0xd) => "sqdmull",
            (0, 0xe) => "pmull",
            _ => return unk(),
        };
        let two = if q == 1 { "2" } else { "" };
        let da = varr(size + 1, 1);
        let sa = varr(size, q);
        return mk(
            format!("{mn}{two} v{rd}.{da}, v{rn}.{sa}, v{rm}.{sa}"),
            Flow::Fallthrough,
        );
    }

    if raw & 0x9F00_0400 == 0x0F00_0000 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let opcode = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (_, 0x0) => "mla",
            (_, 0x4) => "mls",
            (_, 0x8) => "mul",
            (0, 0x1) => "fmla",
            (0, 0x5) => "fmls",
            (0, 0x9) => "fmul",
            (1, 0x9) => "fmulx",
            (0, 0x2) => "smlal",
            (1, 0x2) => "umlal",
            (0, 0x6) => "smlsl",
            (1, 0x6) => "umlsl",
            (0, 0xa) => "smull",
            (1, 0xa) => "umull",
            (0, 0x3) => "sqdmlal",
            (0, 0x7) => "sqdmlsl",
            (0, 0xb) => "sqdmull",
            (0, 0xc) => "sqdmulh",
            (0, 0xd) => "sqrdmulh",
            _ => return unk(),
        };
        let is_fp = matches!(opcode, 0x1 | 0x5 | 0x9);
        let arr = if is_fp {
            farr((size >> 1) & 1, q)
        } else {
            varr(size, q)
        };
        let widening = matches!(opcode, 0x2 | 0x6 | 0xa | 0x3 | 0x7 | 0xb);
        let suf = if widening && q == 1 { "2" } else { "" };
        return mk(
            format!("{mn}{suf} v{rd}.{arr}, v{rn}.{arr}, v?.?[?]"),
            Flow::Fallthrough,
        );
    }

    if raw & 0xDF20_0400 == 0x5E20_0400 {
        let u = (raw >> 29) & 1;
        let hi = (raw >> 23) & 1;
        let size = (raw >> 22) & 3;
        let ftype = (raw >> 22) & 1;
        let rm = (raw >> 16) & 0x1f;
        let opcode = (raw >> 11) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x1a) => {
                if hi == 0 {
                    "fadd"
                } else {
                    "fsub"
                }
            }
            (0, 0x1b) => "fmulx",
            (0, 0x1c) => "fcmeq",
            (0, 0x1f) => {
                if hi == 0 {
                    "frecps"
                } else {
                    "frsqrts"
                }
            }
            (1, 0x1a) => "fabd",
            (1, 0x1b) => "fmul",
            (1, 0x1c) => {
                if hi == 0 {
                    "fcmge"
                } else {
                    "fcmgt"
                }
            }
            (1, 0x1d) => {
                if hi == 0 {
                    "facge"
                } else {
                    "facgt"
                }
            }
            (0, 0x10) => "add",
            (1, 0x10) => "sub",
            (1, 0x11) => "cmeq",
            _ => return unk(),
        };
        let _ = size;
        return mk(
            format!(
                "{mn} {}, {}, {}",
                fp_reg(ftype, rd),
                fp_reg(ftype, rn),
                fp_reg(ftype, rm)
            ),
            Flow::Fallthrough,
        );
    }

    if raw & 0xDF3E_0C00 == 0x5E20_0800 {
        let u = (raw >> 29) & 1;
        let hi = (raw >> 23) & 1;
        let opcode = (raw >> 12) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let ftype = (raw >> 22) & 1;
        let mn = match (u, opcode) {
            (0, 0x1a) => {
                if hi == 1 {
                    "fcvtps"
                } else {
                    "fcvtns"
                }
            }
            (0, 0x1b) => {
                if hi == 1 {
                    "fcvtzs"
                } else {
                    "fcvtms"
                }
            }
            (1, 0x1a) => {
                if hi == 1 {
                    "fcvtpu"
                } else {
                    "fcvtnu"
                }
            }
            (1, 0x1b) => {
                if hi == 1 {
                    "fcvtzu"
                } else {
                    "fcvtmu"
                }
            }
            (0, 0x1d) => {
                if hi == 1 {
                    "frecpe"
                } else {
                    "scvtf"
                }
            }
            (1, 0x1d) => {
                if hi == 1 {
                    "frsqrte"
                } else {
                    "ucvtf"
                }
            }
            (0, 0x0c) => "fcmgt",
            (1, 0x0c) => "fcmge",
            (0, 0x0d) => "fcmeq",
            (1, 0x0d) => "fcmle",
            (0, 0x0e) => "fcmlt",
            (1, 0x1f) => "fsqrt",
            _ => return unk(),
        };
        return mk(
            format!("{mn} {}, {}", fp_reg(ftype, rd), fp_reg(ftype, rn)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xDFE0_8400 == 0x5E00_0400 {
        let imm5 = (raw >> 16) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let size = imm5.trailing_zeros().min(3);
        let ft = match size {
            0 => 0,
            1 => 3,
            2 => 0,
            _ => 1,
        };
        return mk(
            format!("mov {}, v{rn}.?[?]", fp_reg(ft, rd)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xDF00_0400 == 0x5F00_0000 {
        let u = (raw >> 29) & 1;
        let size = (raw >> 22) & 3;
        let opcode = (raw >> 12) & 0xf;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x1) => "fmla",
            (0, 0x5) => "fmls",
            (0, 0x9) => "fmul",
            (1, 0x9) => "fmulx",
            (0, 0x3) => "sqdmlal",
            (0, 0x7) => "sqdmlsl",
            (0, 0xb) => "sqdmull",
            (0, 0xc) => "sqdmulh",
            (0, 0xd) => "sqrdmulh",
            _ => return unk(),
        };
        let ftype = (size >> 1) & 1;
        return mk(
            format!("{mn} {}, {}, v?.?[?]", fp_reg(ftype, rd), fp_reg(ftype, rn)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xBF00_0000 == 0x0D00_0000 {
        let l = (raw >> 22) & 1;
        let r = (raw >> 21) & 1;
        let opcode = (raw >> 13) & 0x7;
        let rn = (raw >> 5) & 0x1f;
        let rt = raw & 0x1f;
        let n = if r == 1 { 2 } else { 1 } + if opcode & 1 == 1 { 2 } else { 0 };
        let mn = if opcode == 0b110 && l == 1 {
            format!("ld{n}r")
        } else if l == 1 {
            format!("ld{n}")
        } else {
            format!("st{n}")
        };
        return mk(
            format!("{mn} {{v{rt}.?}}[?], [{}]", reg(rn, true, true)),
            Flow::Fallthrough,
        );
    }

    if raw & 0xFFFF_F01F == 0xD503_301F {
        let crm = (raw >> 8) & 0xf;
        let opc = (raw >> 5) & 0x7;
        let mn = match opc {
            0b100 => "dsb",
            0b101 => "dmb",
            0b110 => "isb",
            _ => return unk(),
        };
        let opt = match crm {
            0b1111 => "sy".to_string(),
            0b1110 => "st".to_string(),
            0b1101 => "ld".to_string(),
            0b1011 => "ish".to_string(),
            0b1010 => "ishst".to_string(),
            0b1001 => "ishld".to_string(),
            0b0111 => "nsh".to_string(),
            0b0011 => "osh".to_string(),
            other => format!("#0x{other:x}"),
        };
        return mk(format!("{mn} {opt}"), Flow::Fallthrough);
    }

    if raw & 0x9FF8_0000 == 0x0F00_0000 {
        let q = (raw >> 30) & 1;
        let op = (raw >> 29) & 1;
        let cmode = (raw >> 12) & 0xf;
        let abc = (raw >> 16) & 0x7;
        let defgh = (raw >> 5) & 0x1f;
        let imm8 = (abc << 5) | defgh;
        let rd = raw & 0x1f;
        let mn = if op == 0 {
            match cmode {
                0xF => "fmov",
                0xC..=0xE => "movi",
                c if c & 1 == 0 => "movi",
                _ => "orr",
            }
        } else {
            match cmode {
                0xF => "fmov",
                0xE => "movi",
                0xC | 0xD => "mvni",
                c if c & 1 == 0 => "mvni",
                _ => "bic",
            }
        };
        let arr = if q == 1 { "16b" } else { "8b" };
        return mk(format!("{mn} v{rd}.{arr}, #0x{imm8:x}"), Flow::Fallthrough);
    }

    if raw & 0x9F80_0400 == 0x0F00_0400 {
        let q = (raw >> 30) & 1;
        let u = (raw >> 29) & 1;
        let immh = (raw >> 19) & 0xf;
        if immh == 0 {
            return unk();
        }
        let opcode = (raw >> 11) & 0x1f;
        let rn = (raw >> 5) & 0x1f;
        let rd = raw & 0x1f;
        let mn = match (u, opcode) {
            (0, 0x00) => "sshr",
            (1, 0x00) => "ushr",
            (0, 0x02) => "ssra",
            (1, 0x02) => "usra",
            (0, 0x04) => "srshr",
            (1, 0x04) => "urshr",
            (0, 0x06) => "srsra",
            (1, 0x06) => "ursra",
            (1, 0x08) => "sri",
            (0, 0x0a) => "shl",
            (1, 0x0a) => "sli",
            (1, 0x0c) => "sqshlu",
            (0, 0x0e) => "sqshl",
            (1, 0x0e) => "uqshl",
            (0, 0x10) => "shrn",
            (1, 0x10) => "sqshrun",
            (0, 0x12) => "sqshrn",
            (1, 0x12) => "uqshrn",
            (0, 0x14) => "sshll",
            (1, 0x14) => "ushll",
            (0, 0x1c) => "scvtf",
            (1, 0x1c) => "ucvtf",
            (0, 0x1f) => "fcvtzs",
            (1, 0x1f) => "fcvtzu",
            _ => return unk(),
        };
        let size = if immh & 0x8 != 0 {
            3
        } else if immh & 0x4 != 0 {
            2
        } else if immh & 0x2 != 0 {
            1
        } else {
            0
        };
        let two = q == 1 && matches!(opcode, 0x14 | 0x10 | 0x12);
        let suf = if two { "2" } else { "" };
        let a = varr(size, q);
        return mk(
            format!("{mn}{suf} v{rd}.{a}, v{rn}.{a}, #?"),
            Flow::Fallthrough,
        );
    }

    unk()
}

fn simm(v: i64) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn shift_str(shtype: u32, amount: u32) -> String {
    if amount == 0 {
        return String::new();
    }
    let s = match shtype {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        _ => "ror",
    };
    format!(", {s} #{amount}")
}

fn varr(size: u32, q: u32) -> &'static str {
    match (size, q) {
        (0, 0) => "8b",
        (0, 1) => "16b",
        (1, 0) => "4h",
        (1, 1) => "8h",
        (2, 0) => "2s",
        (2, 1) => "4s",
        (3, 0) => "1d",
        _ => "2d",
    }
}

fn farr(hi: u32, q: u32) -> &'static str {
    if hi == 1 {
        "2d"
    } else if q == 1 {
        "4s"
    } else {
        "2s"
    }
}

fn fp_reg(ftype: u32, n: u32) -> String {
    let p = match ftype {
        0 => 's',
        1 => 'd',
        3 => 'h',
        _ => 'v',
    };
    format!("{p}{n}")
}

fn simd_ls_size(size: u32, opc: u32) -> (char, u32) {
    if opc & 0b10 != 0 {
        ('q', 4)
    } else {
        match size {
            0 => ('b', 0),
            1 => ('h', 1),
            2 => ('s', 2),
            _ => ('d', 3),
        }
    }
}

fn decode_bitmask(n: u32, imms: u32, immr: u32, datasize: u32) -> Option<u64> {
    let x = ((n & 1) << 6) | ((!imms) & 0x3f);
    if x == 0 {
        return None;
    }
    let len = 31 - x.leading_zeros();
    if len == 0 {
        return None;
    }
    let esize = 1u32 << len;
    if esize > datasize {
        return None;
    }
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let s1 = s + 1;
    let welem: u64 = if s1 >= 64 { u64::MAX } else { (1u64 << s1) - 1 };
    let emask: u64 = if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };
    let rot = r % esize;
    let elem = if rot == 0 {
        welem & emask
    } else {
        ((welem >> rot) | (welem << (esize - rot))) & emask
    };
    let mut result: u64 = 0;
    let mut pos = 0u32;
    while pos < datasize {
        result |= elem << pos;
        pos += esize;
    }
    if datasize < 64 {
        result &= (1u64 << datasize) - 1;
    }
    Some(result)
}

fn vfp_expand_imm(imm8: u32) -> f64 {
    let sign = (imm8 >> 7) & 1;
    let b = (imm8 >> 6) & 1;
    let cd = (imm8 >> 4) & 0x3;
    let frac = (imm8 & 0xf) as u64;
    let e_hi = (1 - b) as u64;
    let e_mid = if b == 1 { 0xffu64 } else { 0 };
    let exp = (e_hi << 10) | (e_mid << 2) | (cd as u64);
    let bits = ((sign as u64) << 63) | (exp << 52) | (frac << 48);
    f64::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(raw: u32) -> String {
        decode(raw, 0x1000).text
    }

    #[test]
    fn branches_and_returns() {
        assert_eq!(decode(0xD65F03C0, 0x1000).flow, Flow::Return);
        assert_eq!(t(0xD65F03C0), "ret");
        assert_eq!(t(0xD503201F), "nop");
        assert_eq!(decode(0x94000000, 0x1000).flow, Flow::Call(0x1000));
        assert_eq!(decode(0x14000004, 0x1000).flow, Flow::Branch(0x1010));
        assert_eq!(t(0x14000004), "b 0x1010");
    }

    #[test]
    fn cond_branch_and_cbz() {
        let d = decode(0x54000040, 0x1000);
        assert_eq!(d.flow, Flow::CondBranch(0x1008));
        assert_eq!(d.text, "b.eq 0x1008");
        let d = decode(0xB4000040, 0x1000);
        assert_eq!(d.text, "cbz x0, 0x1008");
        assert_eq!(d.flow, Flow::CondBranch(0x1008));
    }

    #[test]
    fn moves() {
        assert_eq!(t(0xD2800020), "mov x0, #0x1");
        assert_eq!(t(0x528000E1), "mov w1, #0x7");
    }

    #[test]
    fn add_sub_cmp() {
        assert_eq!(t(0x91004020), "add x0, x1, #0x10");
        assert_eq!(t(0xF1000C1F), "cmp x0, #0x3");
    }

    #[test]
    fn loads_stores() {
        assert_eq!(t(0xF9400020), "ldr x0, [x1]");
        assert_eq!(t(0xF9000FE0), "str x0, [sp, #0x18]");
    }

    #[test]
    fn mov_reg_and_ret_reg() {
        assert_eq!(t(0xAA0103E0), "mov x0, x1");
    }

    #[test]
    fn unknown_is_word() {
        assert_eq!(t(0x9e7e0000), ".word 0x9e7e0000");
    }

    #[test]
    fn extra_isa_classes() {
        assert_eq!(t(0x1a8883e9), "csel w9, wzr, w8, hi");
        assert_eq!(t(0x9b027c20), "mul x0, x1, x2");
        assert_eq!(t(0x531c6c20), "lsl w0, w1, #4");
        assert_eq!(t(0xf85f8020), "ldur x0, [x1, #-0x8]");
        assert_eq!(t(0x1ac20820), "udiv w0, w1, w2");
    }

    fn m(raw: u32) -> String {
        t(raw).split_whitespace().next().unwrap_or("").to_string()
    }

    #[test]
    fn signed_and_simd_loads() {
        assert_eq!(t(0xb98002a8), "ldrsw x8, [x21]");
        assert_eq!(m(0x39c0010a), "ldrsb");
        assert_eq!(m(0xb89503a0), "ldursw");
        assert_eq!(m(0x3dc16100), "ldr");
        assert_eq!(t(0x3dc16100), "ldr q0, [x8, #0x580]");
        assert_eq!(t(0x3c900100), "stur q0, [x8, #-0x100]");
    }

    #[test]
    fn logical_immediate() {
        assert_eq!(t(0x927ff928), "and x8, x9, #0xfffffffffffffffe");
        assert_eq!(t(0x320003e2), "mov w2, #0x1");
        assert_eq!(m(0x52000348), "eor");
        assert_eq!(m(0x7200011f), "tst");
    }

    #[test]
    fn fp_scalar_family() {
        assert_eq!(t(0x1e622020), "fcmp d1, d2");
        assert_eq!(t(0x1e610808), "fmul d8, d0, d1");
        assert_eq!(m(0x1e202800), "fadd");
        assert_eq!(m(0x1e603901), "fsub");
        assert_eq!(m(0x1e601908), "fdiv");
        assert_eq!(t(0x1e629002), "fmov d2, #5.00000000");
        assert_eq!(m(0x1e6202a0), "scvtf");
        assert_eq!(m(0x1e780001), "fcvtzs");
        assert_eq!(m(0x1e681d2a), "fcsel");
    }

    #[test]
    fn atomics_and_exclusives() {
        assert_eq!(t(0xc85ffe89), "ldaxr x9, [x20]");
        assert_eq!(t(0x08dffd08), "ldarb w8, [x8]");
        assert_eq!(m(0xc808ff80), "stlxr");
        assert_eq!(m(0xc89ffd17), "stlr");
    }

    #[test]
    fn misc_new_classes() {
        assert_eq!(t(0xd4200020), "brk #0x1");
        assert_eq!(t(0x5ac01129), "clz w9, w9");
        assert_eq!(t(0xdac00128), "rbit x8, x9");
        assert_eq!(m(0xfa401904), "ccmp");
        assert_eq!(m(0x8b2ac108), "add");
        assert_eq!(t(0x9b357d2a), "smull x10, w9, w21");
        assert_eq!(m(0x4f00e400), "movi");
        assert_eq!(m(0x00000010), "udf");
    }

    #[test]
    fn neon_vector_families() {
        assert_eq!(m(0x2e22dc84), "fmul");
        assert_eq!(m(0x4e22ce54), "fmla");
        assert_eq!(m(0x4e20d440), "fadd");
        assert_eq!(m(0x0ea2d421), "fsub");
        assert_eq!(m(0x6e20d400), "faddp");
        assert_eq!(m(0x4e201c85), "and");
        assert_eq!(m(0x4ea41c63), "orr");
        assert_eq!(m(0x6e611c40), "bsl");
        assert_eq!(m(0x4ee38421), "add");
        assert_eq!(t(0x4ea81d00), "mov v0.16b, v8.16b");
        assert_eq!(m(0x4e080e80), "dup");
        assert_eq!(m(0x0e0e3c8b), "umov");
        assert_eq!(m(0x6e004000), "ext");
        assert_eq!(m(0x4e9038a5), "zip1");
        assert_eq!(m(0x0e8b794f), "zip2");
        assert_eq!(m(0x4e801802), "uzp1");
        assert_eq!(m(0x6ea0fa24), "fneg");
        assert_eq!(m(0x4ea1d800), "frecpe");
        assert_eq!(m(0x4ea00a05), "rev64");
        assert_eq!(m(0x4e020066), "tbl");
        assert_eq!(m(0x4cdf7003), "ld1");
        assert_eq!(t(0xd5033f5f), "clrex");
    }

    #[test]
    fn indexed_scalar_and_misc_simd() {
        assert_eq!(m(0x4f801023), "fmla");
        assert_eq!(m(0x0f845061), "fmls");
        assert_eq!(m(0x4f408261), "mul");
        assert_eq!(m(0x5fa09042), "fmul");
        assert_eq!(t(0x93c08008), "ror x8, x0, #0x20");
        assert_eq!(t(0x1a090149), "adc w9, w10, w9");
        assert_eq!(t(0xba1101b7), "adcs x23, x13, x17");
        assert_eq!(m(0x4f095421), "shl");
        assert_eq!(m(0x0f20a400), "sshll");
        assert_eq!(m(0x2f10a484), "ushll");
        assert_eq!(m(0x0e67c0d4), "smull");
        assert_eq!(t(0x5e61d800), "scvtf d0, d0");
        assert_eq!(m(0x7ee0d500), "fabd");
        assert_eq!(m(0x5e0c0422), "mov");
        assert_eq!(m(0x4d408101), "ld1");
    }

    #[test]
    fn cmp_records_flags_and_bcond_carries_code() {
        let cmp = decode(0xF1000C1F, 0x1000);
        let f = cmp.flags.expect("cmp should set flags");
        assert_eq!(f.kind, FlagKind::Cmp);
        assert_eq!(f.a, "x0");
        assert_eq!(f.b, "0x3");
        let bne = decode(0x54000041, 0x1000);
        assert_eq!(bne.cond, Some(1));
        assert_eq!(bne.flow, Flow::CondBranch(0x1008));
    }
}
