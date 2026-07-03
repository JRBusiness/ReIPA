pub mod type_encoding;

use reipa_image::{extract_string_section, FoundString};
use reipa_macho::chained_fixups::FixupTarget;
use reipa_macho::fat::select_arm64_slice;
use reipa_macho::reader::Reader;
use reipa_macho::MachOImage;
use std::collections::HashMap;

pub struct ObjcStrings {
    pub selectors: Vec<FoundString>,
    pub class_names: Vec<FoundString>,
    pub method_types: Vec<FoundString>,
}

impl ObjcStrings {
    fn empty() -> ObjcStrings {
        ObjcStrings {
            selectors: Vec::new(),
            class_names: Vec::new(),
            method_types: Vec::new(),
        }
    }
}

pub fn parse_objc_strings(buf: &[u8]) -> reipa_macho::Result<ObjcStrings> {
    let macho = MachOImage::parse(buf)?;
    let slice = select_arm64_slice(buf)?;
    let sdata = slice.data;
    let mut out = ObjcStrings::empty();

    for seg in &macho.segments {
        for sect in &seg.sections {
            match sect.sectname.as_str() {
                "__objc_methname" => out.selectors.extend(extract_string_section(sdata, sect)),
                "__objc_classname" => out.class_names.extend(extract_string_section(sdata, sect)),
                "__objc_methtype" => out.method_types.extend(extract_string_section(sdata, sect)),
                _ => {}
            }
        }
    }
    Ok(out)
}

pub struct ObjcMethod {
    pub name: String,
    pub types: String,
    pub imp: u64,
}

pub struct ObjcIvar {
    pub name: String,
    pub type_enc: String,
    pub offset: u32,
}

pub struct ObjcClass {
    pub address: u64,
    pub name: String,
    pub superclass: Option<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub protocols: Vec<String>,
}

pub struct ObjcCategory {
    pub name: String,
    pub class_name: Option<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub protocols: Vec<String>,
}

const OBJC_CLASS_SUPER_OFF: usize = 8;
const OBJC_CLASS_BITS_OFF: usize = 32;
const FAST_DATA_MASK: u64 = 0x0000_7fff_ffff_fff8;
const CLASS_RO_NAME_OFF: usize = 24;
const CLASS_RO_METHODS_OFF: usize = 32;
const CLASS_RO_PROTOCOLS_OFF: usize = 40;
const CLASS_RO_IVARS_OFF: usize = 48;
const PROTOCOL_NAME_OFF: usize = 8;
const SMALL_METHOD_LIST_FLAG: u32 = 0x8000_0000;
const CATEGORY_CLS_OFF: usize = 8;
const CATEGORY_INST_METHODS_OFF: usize = 16;
const CATEGORY_CLASS_METHODS_OFF: usize = 24;
const CATEGORY_PROTOCOLS_OFF: usize = 32;

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Reader::at(data, offset).ok()?.read_u32().ok()
}

fn u32_vm(m: &MachOImage, d: &[u8], vm: u64) -> Option<u32> {
    u32_at(d, m.vmaddr_to_offset(vm)?)
}

fn cstr_vm(m: &MachOImage, d: &[u8], vm: u64) -> Option<String> {
    read_cstr(d, m.vmaddr_to_offset(vm)?)
}

fn rel(base_vm: u64, off: i32) -> u64 {
    (base_vm as i64).wrapping_add(off as i64) as u64
}

struct Resolver {
    chained: HashMap<u64, FixupTarget>,
    binds: HashMap<u64, String>,
}

impl Resolver {
    fn new(m: &MachOImage) -> Resolver {
        let mut chained = HashMap::new();
        let mut binds: HashMap<u64, String> = HashMap::new();
        for b in &m.binds {
            binds.insert(b.address, b.symbol.clone());
        }
        for f in &m.chained_fixups {
            if let FixupTarget::Bind(sym) = &f.target {
                binds.insert(f.address, sym.clone());
            }
            chained.insert(f.address, f.target.clone());
        }
        Resolver { chained, binds }
    }

    fn follow(&self, m: &MachOImage, d: &[u8], field_vm: u64) -> Option<u64> {
        match self.chained.get(&field_vm) {
            Some(FixupTarget::Rebase(t)) => Some(*t),
            Some(FixupTarget::Bind(_)) => None,
            None => match m.read_u64_at(d, m.vmaddr_to_offset(field_vm)?)? {
                0 => None,
                v => Some(v),
            },
        }
    }

    fn bind_class_name(&self, field_vm: u64) -> Option<String> {
        let sym = self.binds.get(&field_vm)?;
        Some(
            sym.strip_prefix("_OBJC_CLASS_$_")
                .unwrap_or(sym)
                .to_string(),
        )
    }
}

fn class_name_at(r: &Resolver, m: &MachOImage, d: &[u8], class_vm: u64) -> Option<String> {
    let ro_vm = r.follow(m, d, class_vm.wrapping_add(OBJC_CLASS_BITS_OFF as u64))? & FAST_DATA_MASK;
    let name_vm = r.follow(m, d, ro_vm.wrapping_add(CLASS_RO_NAME_OFF as u64))?;
    cstr_vm(m, d, name_vm)
}

fn read_method_list(r: &Resolver, m: &MachOImage, d: &[u8], list_vm: u64) -> Vec<ObjcMethod> {
    let mut out = Vec::new();
    if list_vm == 0 {
        return out;
    }
    let list_off = match m.vmaddr_to_offset(list_vm) {
        Some(o) => o,
        None => return out,
    };
    let eaf = match u32_at(d, list_off) {
        Some(v) => v,
        None => return out,
    };
    let count = match u32_at(d, list_off + 4) {
        Some(v) => v as usize,
        None => return out,
    };
    let is_small = eaf & SMALL_METHOD_LIST_FLAG != 0;
    let entsize: u64 = if is_small { 12 } else { 24 };
    let avail = d.len().saturating_sub(list_off + 8) as u64;
    let count = count.min((avail / entsize) as usize);

    for i in 0..count {
        let e_vm = list_vm
            .wrapping_add(8)
            .wrapping_add((i as u64).wrapping_mul(entsize));
        if is_small {
            let name = u32_vm(m, d, e_vm).and_then(|off| {
                let selref_vm = rel(e_vm, off as i32);
                let sel_str_vm = r.follow(m, d, selref_vm)?;
                cstr_vm(m, d, sel_str_vm)
            });
            let types = u32_vm(m, d, e_vm.wrapping_add(4))
                .and_then(|off| cstr_vm(m, d, rel(e_vm.wrapping_add(4), off as i32)));
            let imp = u32_vm(m, d, e_vm.wrapping_add(8))
                .map(|off| rel(e_vm.wrapping_add(8), off as i32))
                .unwrap_or(0);
            if let Some(name) = name {
                out.push(ObjcMethod {
                    name,
                    types: types.unwrap_or_default(),
                    imp,
                });
            }
        } else {
            let name = r.follow(m, d, e_vm).and_then(|p| cstr_vm(m, d, p));
            let types = r
                .follow(m, d, e_vm.wrapping_add(8))
                .and_then(|p| cstr_vm(m, d, p));
            let imp = r.follow(m, d, e_vm.wrapping_add(16)).unwrap_or(0);
            if let Some(name) = name {
                out.push(ObjcMethod {
                    name,
                    types: types.unwrap_or_default(),
                    imp,
                });
            }
        }
    }
    out
}

fn read_ivar_list(r: &Resolver, m: &MachOImage, d: &[u8], list_vm: u64) -> Vec<ObjcIvar> {
    let mut out = Vec::new();
    if list_vm == 0 {
        return out;
    }
    let list_off = match m.vmaddr_to_offset(list_vm) {
        Some(o) => o,
        None => return out,
    };
    let entsize = match u32_at(d, list_off) {
        Some(v) if v != 0 => v as u64,
        _ => return out,
    };
    let count = match u32_at(d, list_off + 4) {
        Some(v) => v as usize,
        None => return out,
    };
    let avail = d.len().saturating_sub(list_off + 8) as u64;
    let count = count.min((avail / entsize) as usize);

    for i in 0..count {
        let iv_vm = list_vm
            .wrapping_add(8)
            .wrapping_add((i as u64).wrapping_mul(entsize));
        let offset = r
            .follow(m, d, iv_vm)
            .and_then(|p| u32_vm(m, d, p))
            .unwrap_or(0);
        let name = r
            .follow(m, d, iv_vm.wrapping_add(8))
            .and_then(|p| cstr_vm(m, d, p))
            .unwrap_or_default();
        let type_enc = r
            .follow(m, d, iv_vm.wrapping_add(16))
            .and_then(|p| cstr_vm(m, d, p))
            .unwrap_or_default();
        out.push(ObjcIvar {
            name,
            type_enc,
            offset,
        });
    }
    out
}

fn read_class_methods(r: &Resolver, m: &MachOImage, d: &[u8], class_vm: u64) -> Vec<ObjcMethod> {
    let meta_vm = match r.follow(m, d, class_vm) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let meta_ro_vm = match r.follow(m, d, meta_vm.wrapping_add(OBJC_CLASS_BITS_OFF as u64)) {
        Some(bits) => bits & FAST_DATA_MASK,
        None => return Vec::new(),
    };
    let methods_vm = r
        .follow(m, d, meta_ro_vm.wrapping_add(CLASS_RO_METHODS_OFF as u64))
        .unwrap_or(0);
    read_method_list(r, m, d, methods_vm)
}

fn read_protocol_list(r: &Resolver, m: &MachOImage, d: &[u8], list_vm: u64) -> Vec<String> {
    let mut out = Vec::new();
    if list_vm == 0 {
        return out;
    }
    let list_off = match m.vmaddr_to_offset(list_vm) {
        Some(o) => o,
        None => return out,
    };
    let count = match m.read_u64_at(d, list_off) {
        Some(v) => v as usize,
        None => return out,
    };
    let avail = d.len().saturating_sub(list_off + 8);
    let count = count.min(avail / 8);
    for i in 0..count {
        let proto_field_vm = list_vm
            .wrapping_add(8)
            .wrapping_add((i as u64).wrapping_mul(8));
        let proto_vm = match r.follow(m, d, proto_field_vm) {
            Some(v) => v,
            None => continue,
        };
        let name = r
            .follow(m, d, proto_vm.wrapping_add(PROTOCOL_NAME_OFF as u64))
            .and_then(|nv| cstr_vm(m, d, nv));
        if let Some(n) = name {
            out.push(n);
        }
    }
    out
}

pub fn parse_objc_classes(buf: &[u8]) -> reipa_macho::Result<Vec<ObjcClass>> {
    let macho = MachOImage::parse(buf)?;
    let slice = select_arm64_slice(buf)?;
    let sdata = slice.data;

    let mut out = Vec::new();
    let classlist = match macho.section_by_name("__objc_classlist") {
        Some(s) => s,
        None => return Ok(out),
    };

    let resolver = Resolver::new(&macho);
    let list_addr = classlist.addr;
    let base = classlist.offset as usize;
    let max_by_buf = sdata.len().saturating_sub(base) / 8;
    let count = ((classlist.size / 8) as usize).min(max_by_buf);
    for i in 0..count {
        let entry_vm = list_addr.wrapping_add((i as u64).wrapping_mul(8));
        let class_vm = match resolver.follow(&macho, sdata, entry_vm) {
            Some(v) => v,
            None => continue,
        };
        let ro_vm = match resolver.follow(
            &macho,
            sdata,
            class_vm.wrapping_add(OBJC_CLASS_BITS_OFF as u64),
        ) {
            Some(bits) => bits & FAST_DATA_MASK,
            None => continue,
        };
        let name = match resolver
            .follow(&macho, sdata, ro_vm.wrapping_add(CLASS_RO_NAME_OFF as u64))
            .and_then(|nv| cstr_vm(&macho, sdata, nv))
        {
            Some(n) => n,
            None => continue,
        };

        let super_field = class_vm.wrapping_add(OBJC_CLASS_SUPER_OFF as u64);
        let superclass = match resolver.follow(&macho, sdata, super_field) {
            Some(v) => class_name_at(&resolver, &macho, sdata, v),
            None => resolver.bind_class_name(super_field),
        };
        let methods_vm = resolver
            .follow(
                &macho,
                sdata,
                ro_vm.wrapping_add(CLASS_RO_METHODS_OFF as u64),
            )
            .unwrap_or(0);
        let instance_methods = read_method_list(&resolver, &macho, sdata, methods_vm);
        let class_methods = read_class_methods(&resolver, &macho, sdata, class_vm);
        let ivars_vm = resolver
            .follow(&macho, sdata, ro_vm.wrapping_add(CLASS_RO_IVARS_OFF as u64))
            .unwrap_or(0);
        let ivars = read_ivar_list(&resolver, &macho, sdata, ivars_vm);
        let protos_vm = resolver
            .follow(
                &macho,
                sdata,
                ro_vm.wrapping_add(CLASS_RO_PROTOCOLS_OFF as u64),
            )
            .unwrap_or(0);
        let protocols = read_protocol_list(&resolver, &macho, sdata, protos_vm);

        out.push(ObjcClass {
            address: class_vm,
            name,
            superclass,
            instance_methods,
            class_methods,
            ivars,
            protocols,
        });
    }
    Ok(out)
}

pub fn parse_objc_categories(buf: &[u8]) -> reipa_macho::Result<Vec<ObjcCategory>> {
    let macho = MachOImage::parse(buf)?;
    let slice = select_arm64_slice(buf)?;
    let sdata = slice.data;

    let mut out = Vec::new();
    let catlist = match macho.section_by_name("__objc_catlist") {
        Some(s) => s,
        None => return Ok(out),
    };
    let resolver = Resolver::new(&macho);
    let list_addr = catlist.addr;
    let base = catlist.offset as usize;
    let max_by_buf = sdata.len().saturating_sub(base) / 8;
    let count = ((catlist.size / 8) as usize).min(max_by_buf);

    for i in 0..count {
        let entry_vm = list_addr.wrapping_add((i as u64).wrapping_mul(8));
        let cat_vm = match resolver.follow(&macho, sdata, entry_vm) {
            Some(v) => v,
            None => continue,
        };
        let name = match resolver
            .follow(&macho, sdata, cat_vm)
            .and_then(|nv| cstr_vm(&macho, sdata, nv))
        {
            Some(n) => n,
            None => continue,
        };
        let cls_field = cat_vm.wrapping_add(CATEGORY_CLS_OFF as u64);
        let class_name = match resolver.follow(&macho, sdata, cls_field) {
            Some(v) => class_name_at(&resolver, &macho, sdata, v),
            None => resolver.bind_class_name(cls_field),
        };
        let inst_vm = resolver
            .follow(
                &macho,
                sdata,
                cat_vm.wrapping_add(CATEGORY_INST_METHODS_OFF as u64),
            )
            .unwrap_or(0);
        let instance_methods = read_method_list(&resolver, &macho, sdata, inst_vm);
        let cls_vm = resolver
            .follow(
                &macho,
                sdata,
                cat_vm.wrapping_add(CATEGORY_CLASS_METHODS_OFF as u64),
            )
            .unwrap_or(0);
        let class_methods = read_method_list(&resolver, &macho, sdata, cls_vm);
        let protos_vm = resolver
            .follow(
                &macho,
                sdata,
                cat_vm.wrapping_add(CATEGORY_PROTOCOLS_OFF as u64),
            )
            .unwrap_or(0);
        let protocols = read_protocol_list(&resolver, &macho, sdata, protos_vm);

        out.push(ObjcCategory {
            name,
            class_name,
            instance_methods,
            class_methods,
            protocols,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reipa_macho::consts::*;

    fn build_with_objc_strings() -> Vec<u8> {
        let methname = b"init\0dealloc\0";
        let classname = b"Foo\0Bar\0";
        let methtype = b"v16@0:8\0";

        fn sect_bytes(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec();
            sn.resize(16, 0);
            let mut sg = b"__TEXT".to_vec();
            sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s.extend_from_slice(&0u32.to_le_bytes());
            s
        }

        let nsects = 3u32;
        let seg_body_len = 64 + (nsects as usize) * 80;
        let cmdsize = 8 + seg_body_len;
        let data_start = 32 + cmdsize;

        let off_methname = data_start as u32;
        let off_classname = off_methname + methname.len() as u32;
        let off_methtype = off_classname + classname.len() as u32;

        let mut seg = Vec::new();
        let mut segn = b"__TEXT".to_vec();
        segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&0x4000u64.to_le_bytes());
        seg.extend_from_slice(&0u64.to_le_bytes());
        seg.extend_from_slice(&0x4000u64.to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect_bytes(
            "__objc_methname",
            0x2000,
            methname.len() as u64,
            off_methname,
        ));
        seg.extend_from_slice(&sect_bytes(
            "__objc_classname",
            0x3000,
            classname.len() as u64,
            off_classname,
        ));
        seg.extend_from_slice(&sect_bytes(
            "__objc_methtype",
            0x3100,
            methtype.len() as u64,
            off_methtype,
        ));

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
        v.extend_from_slice(methname);
        v.extend_from_slice(classname);
        v.extend_from_slice(methtype);
        v
    }

    #[test]
    fn parses_all_three_objc_string_pools() {
        let bytes = build_with_objc_strings();
        let objc = parse_objc_strings(&bytes).unwrap();
        let sels: Vec<_> = objc.selectors.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(sels, vec!["init", "dealloc"]);
        assert_eq!(objc.selectors[0].addr, 0x2000);
        let names: Vec<_> = objc.class_names.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(names, vec!["Foo", "Bar"]);
        let types: Vec<_> = objc.method_types.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(types, vec!["v16@0:8"]);
    }

    fn build_with_one_class() -> Vec<u8> {
        let nsects = 1u32;
        let seg_body_len = 64 + (nsects as usize) * 80;
        let cmdsize = 8 + seg_body_len;
        let ds = 32 + cmdsize;

        let addr_class = (ds + 8) as u64;
        let addr_ro = (ds + 48) as u64;
        let addr_name = (ds + 80) as u64;

        let mut data = vec![0u8; 88];
        data[0..8].copy_from_slice(&addr_class.to_le_bytes());
        data[40..48].copy_from_slice(&(addr_ro | 0x3).to_le_bytes());
        data[72..80].copy_from_slice(&addr_name.to_le_bytes());
        data[80..88].copy_from_slice(b"MyClass\0");

        fn sect(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec();
            sn.resize(16, 0);
            let mut sg = b"__DATA".to_vec();
            sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            for _ in 0..7 {
                s.extend_from_slice(&0u32.to_le_bytes());
            }
            s
        }

        let mut seg = Vec::new();
        let mut segn = b"__DATA".to_vec();
        segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&(data.len() as u64).to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect("__objc_classlist", ds as u64, 8, ds as u32));

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
        v.extend_from_slice(&data);
        v
    }

    #[test]
    fn parse_objc_classes_resolves_class_name() {
        let bytes = build_with_one_class();
        let classes = parse_objc_classes(&bytes).unwrap();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "MyClass");
        assert_eq!(classes[0].address, (32 + 152 + 8) as u64);
    }

    #[test]
    fn parse_objc_classes_empty_when_no_classlist() {
        let bytes = build_with_objc_strings();
        let classes = parse_objc_classes(&bytes).unwrap();
        assert!(classes.is_empty());
    }

    fn build_class_with_method_and_ivar() -> Vec<u8> {
        let nsects = 1u32;
        let cmdsize = 8 + 64 + (nsects as usize) * 80;
        let ds = 32 + cmdsize;

        let a = |local: usize| (ds + local) as u64;
        let mut d = vec![0u8; 0xCD];
        let put64 =
            |d: &mut [u8], at: usize, v: u64| d[at..at + 8].copy_from_slice(&v.to_le_bytes());
        let put32 =
            |d: &mut [u8], at: usize, v: u32| d[at..at + 4].copy_from_slice(&v.to_le_bytes());

        put64(&mut d, 0x00, a(0x08));
        put64(&mut d, 0x28, a(0x30));
        put64(&mut d, 0x48, a(0xB0));
        put64(&mut d, 0x50, a(0x68));
        put64(&mut d, 0x60, a(0x7C));
        put32(&mut d, 0x68, 12 | SMALL_METHOD_LIST_FLAG);
        put32(&mut d, 0x6C, 1);
        put32(&mut d, 0x70, 0x38);
        put32(&mut d, 0x74, 0x4C);
        put32(&mut d, 0x78, 0);
        put32(&mut d, 0x7C, 32);
        put32(&mut d, 0x80, 1);
        put64(&mut d, 0x84, a(0xA4));
        put64(&mut d, 0x8C, a(0xC8));
        put64(&mut d, 0x94, a(0xCB));
        put32(&mut d, 0x9C, 0);
        put32(&mut d, 0xA0, 8);
        put32(&mut d, 0xA4, 0x10);
        put64(&mut d, 0xA8, a(0xB8));
        d[0xB0..0xB8].copy_from_slice(b"MyClass\0");
        d[0xB8..0xC0].copy_from_slice(b"doThing\0");
        d[0xC0..0xC8].copy_from_slice(b"v16@0:8\0");
        d[0xC8..0xCB].copy_from_slice(b"_x\0");
        d[0xCB..0xCD].copy_from_slice(b"@\0");

        fn sect(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec();
            sn.resize(16, 0);
            let mut sg = b"__DATA".to_vec();
            sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            for _ in 0..7 {
                s.extend_from_slice(&0u32.to_le_bytes());
            }
            s
        }
        let mut seg = Vec::new();
        let mut segn = b"__DATA".to_vec();
        segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&(d.len() as u64).to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect("__objc_classlist", ds as u64, 8, ds as u32));

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
    fn parse_objc_classes_reads_relative_methods_and_ivars() {
        let bytes = build_class_with_method_and_ivar();
        let classes = parse_objc_classes(&bytes).unwrap();
        assert_eq!(classes.len(), 1);
        let c = &classes[0];
        assert_eq!(c.name, "MyClass");
        assert_eq!(c.instance_methods.len(), 1);
        assert_eq!(c.instance_methods[0].name, "doThing");
        assert_eq!(c.instance_methods[0].types, "v16@0:8");
        assert_eq!(c.ivars.len(), 1);
        assert_eq!(c.ivars[0].name, "_x");
        assert_eq!(c.ivars[0].type_enc, "@");
        assert_eq!(c.ivars[0].offset, 0x10);
    }

    #[test]
    fn parse_objc_classes_bounds_huge_classlist_size() {
        let nsects = 1u32;
        let seg_body_len = 64 + (nsects as usize) * 80;
        let cmdsize = 8 + seg_body_len;
        let ds = 32 + cmdsize;
        let data = vec![0u8; 8];

        fn sect(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec();
            sn.resize(16, 0);
            let mut sg = b"__DATA".to_vec();
            sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            for _ in 0..7 {
                s.extend_from_slice(&0u32.to_le_bytes());
            }
            s
        }

        let mut seg = Vec::new();
        let mut segn = b"__DATA".to_vec();
        segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&(data.len() as u64).to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect(
            "__objc_classlist",
            ds as u64,
            0xFFFF_FFFF_FFFF_FFF8,
            ds as u32,
        ));

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
        v.extend_from_slice(&data);

        let classes = parse_objc_classes(&v).unwrap();
        assert!(classes.is_empty());
    }

    #[test]
    fn read_method_list_no_overflow_on_near_max_list_vm() {
        use reipa_macho::segment::Segment;
        let macho = MachOImage {
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            segments: vec![Segment {
                segname: "__DATA".to_string(),
                vmaddr: u64::MAX - 4,
                vmsize: 4,
                fileoff: 0,
                filesize: 4,
                sections: Vec::new(),
            }],
            symbols: Vec::new(),
            uuid: None,
            encryption: None,
            function_starts: Vec::new(),
            has_chained_fixups: false,
            binds: Vec::new(),
            chained_fixups: Vec::new(),
        };
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(&(12u32 | SMALL_METHOD_LIST_FLAG).to_le_bytes());
        d[4..8].copy_from_slice(&1u32.to_le_bytes());
        let r = Resolver::new(&macho);
        let methods = read_method_list(&r, &macho, &d, u64::MAX - 4);
        assert!(methods.is_empty());
    }

    fn identity_image(len: u64) -> MachOImage {
        MachOImage {
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            segments: vec![reipa_macho::segment::Segment {
                segname: "__DATA".to_string(),
                vmaddr: 0,
                vmsize: len,
                fileoff: 0,
                filesize: len,
                sections: Vec::new(),
            }],
            symbols: Vec::new(),
            uuid: None,
            encryption: None,
            function_starts: Vec::new(),
            has_chained_fixups: false,
            binds: Vec::new(),
            chained_fixups: Vec::new(),
        }
    }

    fn p64(d: &mut [u8], at: usize, v: u64) {
        d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(d: &mut [u8], at: usize, v: u32) {
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn build_with_one_category() -> Vec<u8> {
        let nsects = 1u32;
        let cmdsize = 8 + 64 + (nsects as usize) * 80;
        let ds = 32 + cmdsize;
        let a = |local: usize| (ds + local) as u64;
        let mut d = vec![0u8; 0x8C];
        let p64 = |d: &mut [u8], at: usize, v: u64| d[at..at + 8].copy_from_slice(&v.to_le_bytes());
        p64(&mut d, 0x00, a(0x08));
        p64(&mut d, 0x08, a(0x78));
        p64(&mut d, 0x10, a(0x30));
        p64(&mut d, 0x50, a(0x58));
        p64(&mut d, 0x70, a(0x80));
        d[0x78..0x7E].copy_from_slice(b"MyCat\0");
        d[0x80..0x8C].copy_from_slice(b"TargetClass\0");

        fn sect(name: &str, addr: u64, size: u64, offset: u32) -> Vec<u8> {
            let mut s = Vec::new();
            let mut sn = name.as_bytes().to_vec();
            sn.resize(16, 0);
            let mut sg = b"__DATA".to_vec();
            sg.resize(16, 0);
            s.extend_from_slice(&sn);
            s.extend_from_slice(&sg);
            s.extend_from_slice(&addr.to_le_bytes());
            s.extend_from_slice(&size.to_le_bytes());
            s.extend_from_slice(&offset.to_le_bytes());
            for _ in 0..7 {
                s.extend_from_slice(&0u32.to_le_bytes());
            }
            s
        }
        let mut seg = Vec::new();
        let mut segn = b"__DATA".to_vec();
        segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&(ds as u64).to_le_bytes());
        seg.extend_from_slice(&(d.len() as u64).to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&3u32.to_le_bytes());
        seg.extend_from_slice(&nsects.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect("__objc_catlist", ds as u64, 8, ds as u32));

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
    fn parse_objc_categories_resolves_name_and_class() {
        let bytes = build_with_one_category();
        let cats = parse_objc_categories(&bytes).unwrap();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0].name, "MyCat");
        assert_eq!(cats[0].class_name.as_deref(), Some("TargetClass"));
    }

    #[test]
    fn read_protocol_list_resolves_names() {
        let img = identity_image(0x1000);
        let mut d = vec![0u8; 0x100];
        p64(&mut d, 0x10, 1);
        p64(&mut d, 0x18, 0x30);
        p64(&mut d, 0x38, 0x50);
        d[0x50..0x58].copy_from_slice(b"MyProto\0");
        let r = Resolver::new(&img);
        assert_eq!(
            read_protocol_list(&r, &img, &d, 0x10),
            vec!["MyProto".to_string()]
        );
    }

    #[test]
    fn read_class_methods_via_metaclass() {
        let img = identity_image(0x1000);
        let mut d = vec![0u8; 0x200];
        p64(&mut d, 0x100, 0x120);
        p64(&mut d, 0x140, 0x160);
        p64(&mut d, 0x180, 0x1A0);
        p32(&mut d, 0x1A0, 24);
        p32(&mut d, 0x1A4, 1);
        p64(&mut d, 0x1A8, 0x1D0);
        p64(&mut d, 0x1B0, 0x1E0);
        d[0x1D0..0x1D3].copy_from_slice(b"cm\0");
        d[0x1E0..0x1E8].copy_from_slice(b"v16@0:8\0");
        let r = Resolver::new(&img);
        let ms = read_class_methods(&r, &img, &d, 0x100);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].name, "cm");
        assert_eq!(ms[0].types, "v16@0:8");
    }

    #[test]
    fn resolver_follows_chained_rebase_and_bind() {
        use reipa_macho::chained_fixups::{ChainedFixup, FixupTarget};
        let mut img = identity_image(0x1000);
        img.chained_fixups.push(ChainedFixup {
            address: 0x100,
            target: FixupTarget::Rebase(0x500),
        });
        img.chained_fixups.push(ChainedFixup {
            address: 0x200,
            target: FixupTarget::Bind("_OBJC_CLASS_$_NSObject".to_string()),
        });
        let r = Resolver::new(&img);
        let d = vec![0u8; 0x10];
        assert_eq!(r.follow(&img, &d, 0x100), Some(0x500));
        assert_eq!(r.follow(&img, &d, 0x200), None);
        assert_eq!(r.bind_class_name(0x200).as_deref(), Some("NSObject"));
    }
}
