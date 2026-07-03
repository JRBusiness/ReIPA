use reipa_macho::fat::select_arm64_slice;
use reipa_macho::reader::Reader;
use reipa_macho::MachOImage;

#[derive(Debug, PartialEq, Eq)]
pub enum SwiftKind {
    Class,
    Struct,
    Enum,
    Other,
}

pub struct SwiftType {
    pub kind: SwiftKind,
    pub name: String,
}

const KIND_MASK: u32 = 0x1f;
const KIND_MODULE: u32 = 0;
const KIND_PROTOCOL: u32 = 3;
const KIND_CLASS: u32 = 16;
const KIND_STRUCT: u32 = 17;
const KIND_ENUM: u32 = 18;
const MAX_PARENT_DEPTH: usize = 24;

fn kind_has_name(kind: u32) -> bool {
    matches!(kind, KIND_MODULE | KIND_PROTOCOL | KIND_CLASS | KIND_STRUCT | KIND_ENUM)
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    Reader::at(d, off).ok()?.read_u32().ok()
}

fn cstr_vm(m: &MachOImage, d: &[u8], vm: u64) -> Option<String> {
    let off = m.vmaddr_to_offset(vm)?;
    let rest = d.get(off..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn rel_indirectable(m: &MachOImage, d: &[u8], field_vm: u64) -> Option<u64> {
    let off = m.vmaddr_to_offset(field_vm)?;
    let r = u32_at(d, off)? as i32;
    if r == 0 || (r & 1) == 1 {
        return None;
    }
    Some((field_vm as i64).wrapping_add(r as i64) as u64)
}

fn rel_direct(m: &MachOImage, d: &[u8], field_vm: u64) -> Option<u64> {
    let off = m.vmaddr_to_offset(field_vm)?;
    let r = u32_at(d, off)? as i32;
    if r == 0 {
        return None;
    }
    Some((field_vm as i64).wrapping_add(r as i64) as u64)
}

fn descriptor_name(m: &MachOImage, d: &[u8], desc_vm: u64, depth: usize) -> Option<String> {
    if depth > MAX_PARENT_DEPTH {
        return None;
    }
    let flags = u32_at(d, m.vmaddr_to_offset(desc_vm)?)?;
    let parent = rel_indirectable(m, d, desc_vm.wrapping_add(4))
        .and_then(|pv| descriptor_name(m, d, pv, depth + 1));

    if !kind_has_name(flags & KIND_MASK) {
        return parent;
    }
    let name = rel_direct(m, d, desc_vm.wrapping_add(8)).and_then(|nv| cstr_vm(m, d, nv));
    match (parent, name) {
        (Some(p), Some(n)) => Some(format!("{p}.{n}")),
        (None, Some(n)) => Some(n),
        (Some(p), None) => Some(p),
        (None, None) => None,
    }
}

pub fn parse_swift_types(buf: &[u8]) -> reipa_macho::Result<Vec<SwiftType>> {
    let macho = MachOImage::parse(buf)?;
    let slice = select_arm64_slice(buf)?;
    let sdata = slice.data;

    let mut out = Vec::new();
    let sec = match macho.section_by_name("__swift5_types") {
        Some(s) => s,
        None => return Ok(out),
    };
    let base = sec.offset as usize;
    let max_by_buf = sdata.len().saturating_sub(base) / 4;
    let count = ((sec.size / 4) as usize).min(max_by_buf);

    for i in 0..count {
        let entry_vm = sec.addr.wrapping_add((i as u64).wrapping_mul(4));
        let desc_vm = match rel_indirectable(&macho, sdata, entry_vm) {
            Some(v) => v,
            None => continue,
        };
        let desc_off = match macho.vmaddr_to_offset(desc_vm) {
            Some(o) => o,
            None => continue,
        };
        let flags = match u32_at(sdata, desc_off) {
            Some(v) => v,
            None => continue,
        };
        let kind = match flags & KIND_MASK {
            KIND_CLASS => SwiftKind::Class,
            KIND_STRUCT => SwiftKind::Struct,
            KIND_ENUM => SwiftKind::Enum,
            _ => SwiftKind::Other,
        };
        if let Some(name) = descriptor_name(&macho, sdata, desc_vm, 0) {
            out.push(SwiftType { kind, name });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reipa_macho::consts::*;

    fn build_with_one_swift_type() -> Vec<u8> {
        let nsects = 1u32;
        let cmdsize = 8 + 64 + (nsects as usize) * 80;
        let ds = 32 + cmdsize;

        let mut d = vec![0u8; 0x40];
        let put_i32 = |d: &mut [u8], at: usize, v: i32| d[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put_u32 = |d: &mut [u8], at: usize, v: u32| d[at..at + 4].copy_from_slice(&v.to_le_bytes());

        put_i32(&mut d, 0x00, 8);
        put_u32(&mut d, 0x08, KIND_STRUCT);
        put_i32(&mut d, 0x0C, 0x20 - 0x0C);
        put_i32(&mut d, 0x10, 0x18 - 0x10);
        d[0x18..0x1A].copy_from_slice(b"T\0");
        put_u32(&mut d, 0x20, 0);
        put_i32(&mut d, 0x24, 0);
        put_i32(&mut d, 0x28, 0x30 - 0x28);
        d[0x30..0x32].copy_from_slice(b"M\0");

        fn sect(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec(); sn.resize(16, 0);
            let mut sg = b"__TEXT".to_vec(); sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            for _ in 0..7 { s.extend_from_slice(&0u32.to_le_bytes()); }
            s
        }
        let mut seg = Vec::new();
        let mut segn = b"__TEXT".to_vec(); segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&(d.len() as u64).to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect("__swift5_types", ds as u64, 4, ds as u32));

        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&seg);
        v.extend_from_slice(&d);
        v
    }

    #[test]
    fn parses_one_swift_struct_with_module() {
        let bytes = build_with_one_swift_type();
        let types = parse_swift_types(&bytes).unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, SwiftKind::Struct);
        assert_eq!(types[0].name, "M.T");
    }

    #[test]
    fn empty_when_no_section() {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_swift_types(&v).unwrap().is_empty());
    }
}
