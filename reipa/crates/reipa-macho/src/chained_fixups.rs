use crate::reader::Reader;
use crate::segment::Segment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupTarget {
    Rebase(u64),
    Bind(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedFixup {
    pub address: u64,
    pub target: FixupTarget,
}

const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;

pub fn parse_chained_fixups(
    file: &[u8],
    body: &[u8],
    segments: &[Segment],
    base: u64,
) -> Vec<ChainedFixup> {
    let mut out = Vec::new();
    let mut br = Reader::new(body);
    let dataoff = match br.read_u32() {
        Ok(v) => v as usize,
        Err(_) => return out,
    };
    let datasize = match br.read_u32() {
        Ok(v) => v as usize,
        Err(_) => return out,
    };
    let blob_end = match dataoff.checked_add(datasize) {
        Some(e) if e <= file.len() => e,
        _ => return out,
    };
    let blob = &file[dataoff..blob_end];

    let mut hr = Reader::new(blob);
    let _fixups_version = read_u32(&mut hr);
    let starts_offset = read_u32(&mut hr) as usize;
    let imports_offset = read_u32(&mut hr) as usize;
    let symbols_offset = read_u32(&mut hr) as usize;
    let imports_count = read_u32(&mut hr) as usize;
    let _imports_format = read_u32(&mut hr);
    let _symbols_format = read_u32(&mut hr);

    let imports = parse_imports(blob, imports_offset, imports_count, symbols_offset);

    let seg_count = match u32_at(blob, starts_offset) {
        Some(v) => v as usize,
        None => return out,
    };
    for seg_idx in 0..seg_count {
        let ent_off = match starts_offset.checked_add(4 + seg_idx * 4) {
            Some(o) => o,
            None => break,
        };
        let seg_info_off = match u32_at(blob, ent_off) {
            Some(0) => continue,
            Some(v) => v as usize,
            None => break,
        };
        let start = match starts_offset.checked_add(seg_info_off) {
            Some(o) => o,
            None => continue,
        };
        walk_segment(blob, file, start, seg_idx, segments, base, &imports, &mut out);
    }
    out
}

fn parse_imports(
    blob: &[u8],
    imports_offset: usize,
    imports_count: usize,
    symbols_offset: usize,
) -> Vec<String> {
    let cap = (blob.len() / 4).saturating_add(1);
    let count = imports_count.min(cap);
    let mut out = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let entry = match imports_offset
            .checked_add(i * 4)
            .and_then(|o| u32_at(blob, o))
        {
            Some(v) => v,
            None => break,
        };
        let name_offset = (entry >> 9) as usize;
        let name = symbols_offset
            .checked_add(name_offset)
            .and_then(|o| cstr_at(blob, o))
            .unwrap_or_default();
        out.push(name);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn walk_segment(
    blob: &[u8],
    file: &[u8],
    start: usize,
    seg_idx: usize,
    segments: &[Segment],
    base: u64,
    imports: &[String],
    out: &mut Vec<ChainedFixup>,
) {
    let _size = u32_at(blob, start);
    let page_size = match u16_at(blob, start + 4) {
        Some(v) if v != 0 => v as u64,
        _ => return,
    };
    let pointer_format = match u16_at(blob, start + 6) {
        Some(v @ (DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET)) => v,
        _ => return,
    };
    let segment_offset = match u64_at(blob, start + 8) {
        Some(v) => v,
        None => return,
    };
    let page_count = match u16_at(blob, start + 20) {
        Some(v) => v as usize,
        None => return,
    };
    let seg = match segments.get(seg_idx) {
        Some(s) => s,
        None => return,
    };

    for page in 0..page_count {
        let ps_off = match start.checked_add(22 + page * 2) {
            Some(o) => o,
            None => break,
        };
        let page_start = match u16_at(blob, ps_off) {
            Some(v) => v,
            None => break,
        };
        if page_start == 0xFFFF {
            continue;
        }
        let chain_off = segment_offset
            .wrapping_add((page as u64) * page_size)
            .wrapping_add(page_start as u64);
        walk_chain(file, seg, chain_off, pointer_format, base, imports, out);
    }
}

fn walk_chain(
    file: &[u8],
    seg: &Segment,
    first_off: u64,
    pointer_format: u16,
    base: u64,
    imports: &[String],
    out: &mut Vec<ChainedFixup>,
) {
    let mut off = first_off as usize;
    let max_steps = file.len() / 4 + 1;
    for _ in 0..max_steps {
        let raw = match u64_at(file, off) {
            Some(v) => v,
            None => break,
        };
        let field_vmaddr = seg
            .vmaddr
            .wrapping_add(off as u64)
            .wrapping_sub(seg.fileoff);

        let is_bind = (raw >> 63) & 1 == 1;
        let next = ((raw >> 51) & 0xFFF) as usize;

        if is_bind {
            let ordinal = (raw & 0x00FF_FFFF) as usize;
            if let Some(sym) = imports.get(ordinal) {
                out.push(ChainedFixup {
                    address: field_vmaddr,
                    target: FixupTarget::Bind(sym.clone()),
                });
            }
        } else {
            let target = raw & 0x0000_000F_FFFF_FFFF;
            let high8 = (raw >> 36) & 0xFF;
            let unpacked = (high8 << 56) | target;
            let vmaddr = match pointer_format {
                DYLD_CHAINED_PTR_64_OFFSET => base.wrapping_add(unpacked),
                DYLD_CHAINED_PTR_64 => unpacked,
                _ => base.wrapping_add(unpacked),
            };
            out.push(ChainedFixup {
                address: field_vmaddr,
                target: FixupTarget::Rebase(vmaddr),
            });
        }

        if next == 0 {
            break;
        }
        off = off.wrapping_add(next * 4);
    }
}

fn read_u32(r: &mut Reader) -> u32 {
    r.read_u32().unwrap_or(0)
}
fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    Reader::at(d, off).ok()?.read_u16().ok()
}
fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    Reader::at(d, off).ok()?.read_u32().ok()
}
fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    Reader::at(d, off).ok()?.read_u64().ok()
}
fn cstr_at(d: &[u8], off: usize) -> Option<String> {
    let rest = d.get(off..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rebase_64offset(target36: u64, next: u64) -> u64 {
        (target36 & 0xF_FFFF_FFFF) | ((next & 0xFFF) << 51)
    }

    #[test]
    fn decodes_a_rebase_offset_pointer() {
        let ptr = make_rebase_64offset(0x1234, 0);
        let mut file = ptr.to_le_bytes().to_vec();
        file.resize(0x100, 0);

        let mut blob = Vec::new();
        let starts_off = 28u32;
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&starts_off.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        let seg_info_off = 8u32;
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&seg_info_off.to_le_bytes());
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&0x4000u16.to_le_bytes());
        blob.extend_from_slice(&DYLD_CHAINED_PTR_64_OFFSET.to_le_bytes());
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());

        let dataoff = file.len();
        file.extend_from_slice(&blob);

        let mut cmd = Vec::new();
        cmd.extend_from_slice(&(dataoff as u32).to_le_bytes());
        cmd.extend_from_slice(&(blob.len() as u32).to_le_bytes());

        let seg = Segment {
            segname: "__DATA".to_string(),
            vmaddr: 0x4000,
            vmsize: 0x4000,
            fileoff: 0,
            filesize: 0x100,
            sections: Vec::new(),
        };
        let base = 0x1_0000_0000;
        let fixups = parse_chained_fixups(&file, &cmd, &[seg], base);
        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].address, 0x4000);
        assert_eq!(fixups[0].target, FixupTarget::Rebase(base + 0x1234));
    }

    #[test]
    fn empty_or_malformed_returns_empty() {
        assert!(parse_chained_fixups(&[], &[], &[], 0).is_empty());
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&1000u32.to_le_bytes());
        cmd.extend_from_slice(&1000u32.to_le_bytes());
        assert!(parse_chained_fixups(&[0u8; 16], &cmd, &[], 0).is_empty());
    }
}
