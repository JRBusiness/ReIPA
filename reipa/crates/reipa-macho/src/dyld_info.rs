use crate::reader::Reader;
use crate::segment::Segment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub address: u64,
    pub symbol: String,
}

const BIND_OPCODE_MASK: u8 = 0xF0;
const BIND_IMMEDIATE_MASK: u8 = 0x0F;
const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;

const PTR: u64 = 8;
const MAX_BINDS: usize = 4_000_000;

pub fn parse_dyld_info_binds(file: &[u8], body: &[u8], segments: &[Segment]) -> Vec<Bind> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    let mut u32s = [0u32; 10];
    for slot in u32s.iter_mut() {
        match r.read_u32() {
            Ok(v) => *slot = v,
            Err(_) => return out,
        }
    }
    let streams = [(u32s[2], u32s[3]), (u32s[4], u32s[5]), (u32s[6], u32s[7])];
    for (off, size) in streams {
        let off = off as usize;
        let size = size as usize;
        if size == 0 {
            continue;
        }
        let end = match off.checked_add(size) {
            Some(e) if e <= file.len() => e,
            _ => continue,
        };
        run_bind_stream(&file[off..end], segments, &mut out);
    }
    out
}

fn seg_addr(segments: &[Segment], idx: usize, offset: u64) -> Option<u64> {
    segments.get(idx).map(|s| s.vmaddr.wrapping_add(offset))
}

fn read_symbol(r: &mut Reader) -> String {
    let mut bytes = Vec::new();
    while let Ok(b) = r.read_u8() {
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn run_bind_stream(s: &[u8], segments: &[Segment], out: &mut Vec<Bind>) {
    let mut r = Reader::new(s);
    let mut seg_index = 0usize;
    let mut seg_offset = 0u64;
    let mut symbol = String::new();
    let cap = s.len() as u64 + 1;

    let record = |seg_index: usize, seg_offset: u64, symbol: &str, out: &mut Vec<Bind>| {
        if !symbol.is_empty() {
            if let Some(a) = seg_addr(segments, seg_index, seg_offset) {
                out.push(Bind {
                    address: a,
                    symbol: symbol.to_string(),
                });
            }
        }
    };

    while let Ok(byte) = r.read_u8() {
        if out.len() >= MAX_BINDS {
            break;
        }
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;
        match opcode {
            BIND_OPCODE_DONE => {}
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {}
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let _ = r.read_uleb128();
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {}
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                symbol = read_symbol(&mut r);
            }
            BIND_OPCODE_SET_TYPE_IMM => {}
            BIND_OPCODE_SET_ADDEND_SLEB => {
                let _ = r.read_uleb128();
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm as usize;
                seg_offset = r.read_uleb128().unwrap_or(0);
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                seg_offset = seg_offset.wrapping_add(r.read_uleb128().unwrap_or(0));
            }
            BIND_OPCODE_DO_BIND => {
                record(seg_index, seg_offset, &symbol, out);
                seg_offset = seg_offset.wrapping_add(PTR);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                record(seg_index, seg_offset, &symbol, out);
                let ext = r.read_uleb128().unwrap_or(0);
                seg_offset = seg_offset.wrapping_add(PTR).wrapping_add(ext);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                record(seg_index, seg_offset, &symbol, out);
                seg_offset = seg_offset
                    .wrapping_add(PTR)
                    .wrapping_add((imm as u64).wrapping_mul(PTR));
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = r.read_uleb128().unwrap_or(0).min(cap);
                let skip = r.read_uleb128().unwrap_or(0);
                for _ in 0..count {
                    if out.len() >= MAX_BINDS {
                        break;
                    }
                    record(seg_index, seg_offset, &symbol, out);
                    seg_offset = seg_offset.wrapping_add(PTR).wrapping_add(skip);
                }
            }
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(vmaddr: u64) -> Segment {
        Segment {
            segname: "__DATA".to_string(),
            vmaddr,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            sections: Vec::new(),
        }
    }

    fn build(stream: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let body_len = 40usize;
        let bind_off = body_len;
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(bind_off as u32).to_le_bytes());
        body.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        for _ in 0..6 {
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut file = body.clone();
        file.extend_from_slice(stream);
        (file, body)
    }

    #[test]
    fn resolves_a_do_bind() {
        let mut s = Vec::new();
        s.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
        s.push(0x10);
        s.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        s.extend_from_slice(b"_OBJC_CLASS_$_NSObject\0");
        s.push(BIND_OPCODE_DO_BIND);
        let (file, body) = build(&s);
        let binds = parse_dyld_info_binds(&file, &body, &[seg(0x4000)]);
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].address, 0x4010);
        assert_eq!(binds[0].symbol, "_OBJC_CLASS_$_NSObject");
    }

    #[test]
    fn huge_times_skipping_is_capped() {
        let mut s = Vec::new();
        s.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
        s.push(0x00);
        s.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        s.extend_from_slice(b"_sym\0");
        s.push(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
        s.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        s.push(0x00);
        let (file, body) = build(&s);
        let binds = parse_dyld_info_binds(&file, &body, &[seg(0x4000)]);
        assert!(binds.len() <= s.len() + 1);
    }

    #[test]
    fn stacked_huge_times_skipping_stay_bounded() {
        let mut s = Vec::new();
        s.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
        s.push(0x00);
        s.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        s.extend_from_slice(b"_s\0");
        for _ in 0..50 {
            s.push(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
            s.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
            s.push(0x00);
        }
        let (file, body) = build(&s);
        let binds = parse_dyld_info_binds(&file, &body, &[seg(0x4000)]);
        assert!(binds.len() <= MAX_BINDS);
    }
}
