use reipa_macho::MachOImage;
use reipa_macho::fat::select_arm64_slice;

pub struct FoundString {
    pub addr: u64,
    pub value: String,
}

pub struct Image {
    pub macho: MachOImage,
    pub strings: Vec<FoundString>,
}

pub fn extract_string_section(
    sdata: &[u8],
    sect: &reipa_macho::segment::Section,
) -> Vec<FoundString> {
    let mut out = Vec::new();
    let start = sect.offset as usize;
    let size = sect.size as usize;
    let end = match start.checked_add(size) {
        Some(e) if e <= sdata.len() => e,
        _ => return out,
    };
    let data = &sdata[start..end];
    let mut pos = 0usize;
    while pos < data.len() {
        let rest = &data[pos..];
        let term = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        if term > 0 {
            match sect.addr.checked_add(pos as u64) {
                Some(addr) => out.push(FoundString {
                    addr,
                    value: String::from_utf8_lossy(&rest[..term]).into_owned(),
                }),
                None => break,
            }
        }
        pos += term + 1;
    }
    out
}

impl Image {
    pub fn load(buf: &[u8]) -> reipa_macho::Result<Image> {
        let macho = MachOImage::parse(buf)?;
        let slice = select_arm64_slice(buf)?;
        let sdata = slice.data;
        let mut strings = Vec::new();

        for seg in &macho.segments {
            for sect in &seg.sections {
                if sect.sectname == "__cstring" {
                    strings.extend(extract_string_section(sdata, sect));
                }
            }
        }

        Ok(Image { macho, strings })
    }

    pub fn symbol_at(&self, addr: u64) -> Option<&str> {
        self.macho
            .symbols
            .iter()
            .find(|s| s.value == addr && !s.name.is_empty())
            .map(|s| s.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reipa_macho::consts::*;

    fn build_with_cstring() -> Vec<u8> {
        build_with_cstring_at(0x2000)
    }

    fn build_with_cstring_at(section_addr: u64) -> Vec<u8> {
        build_cstring_macho(section_addr, None)
    }

    fn build_cstring_macho(section_addr: u64, declared_size: Option<u64>) -> Vec<u8> {
        let strings = b"hi\0bye\0";
        let sect_size = declared_size.unwrap_or(strings.len() as u64);
        let mut sect = Vec::new();
        let mut sn = b"__cstring".to_vec(); sn.resize(16, 0);
        let mut sg = b"__TEXT".to_vec(); sg.resize(16, 0);
        sect.extend_from_slice(&sn);
        sect.extend_from_slice(&sg);
        sect.extend_from_slice(&section_addr.to_le_bytes());
        sect.extend_from_slice(&sect_size.to_le_bytes());
        let offset_pos = sect.len();
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());
        sect.extend_from_slice(&0u32.to_le_bytes());

        let mut seg = Vec::new();
        let mut segn = b"__TEXT".to_vec(); segn.resize(16, 0);
        seg.extend_from_slice(&segn);
        seg.extend_from_slice(&0x1000u64.to_le_bytes());
        seg.extend_from_slice(&0x4000u64.to_le_bytes());
        seg.extend_from_slice(&0u64.to_le_bytes());
        seg.extend_from_slice(&0x4000u64.to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&5u32.to_le_bytes());
        seg.extend_from_slice(&1u32.to_le_bytes());
        seg.extend_from_slice(&0u32.to_le_bytes());
        seg.extend_from_slice(&sect);

        let cmdsize = 8 + seg.len();
        let header_and_lc = 32 + cmdsize;
        let string_offset = header_and_lc;
        let seg_prefix = 64usize;
        let abs_offset_pos = seg_prefix + offset_pos;
        seg[abs_offset_pos..abs_offset_pos + 4]
            .copy_from_slice(&(string_offset as u32).to_le_bytes());

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
        v.extend_from_slice(strings);
        v
    }

    #[test]
    fn extract_string_section_reads_nul_separated_with_addrs() {
        use reipa_macho::segment::Section;
        let mut sdata = vec![0u8; 4];
        sdata.extend_from_slice(b"ab\0cd\0");
        let sect = Section {
            sectname: "__objc_methname".to_string(),
            segname: "__TEXT".to_string(),
            addr: 0x5000,
            size: 6,
            offset: 4,
            flags: 0,
        };
        let out = extract_string_section(&sdata, &sect);
        let pairs: Vec<_> = out.iter().map(|s| (s.addr, s.value.as_str())).collect();
        assert_eq!(pairs, vec![(0x5000, "ab"), (0x5003, "cd")]);
    }

    #[test]
    fn extracts_cstrings_with_addresses() {
        let bytes = build_with_cstring();
        let img = Image::load(&bytes).unwrap();
        let vals: Vec<_> = img.strings.iter().map(|s| (s.addr, s.value.as_str())).collect();
        assert!(vals.contains(&(0x2000, "hi")));
        assert!(vals.contains(&(0x2003, "bye")));
    }

    fn wrap_fat(thin: &[u8]) -> Vec<u8> {
        use reipa_macho::consts::*;
        let payload_offset: u32 = 4 + 4 + 20;
        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
        v.extend_from_slice(&payload_offset.to_be_bytes());
        v.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(thin);
        v
    }

    #[test]
    fn extracts_cstrings_from_fat_binary() {
        let thin = build_with_cstring();
        let fat = wrap_fat(&thin);
        let img = Image::load(&fat).unwrap();
        let vals: Vec<_> = img.strings.iter().map(|s| (s.addr, s.value.as_str())).collect();
        assert!(vals.contains(&(0x2000, "hi")), "got {vals:?}");
        assert!(vals.contains(&(0x2003, "bye")), "got {vals:?}");
    }

    #[test]
    fn adversarial_section_addr_does_not_panic() {
        let bytes = build_with_cstring_at(u64::MAX - 1);
        let img = Image::load(&bytes).unwrap();
        let _ = img.strings.len();
    }

    #[test]
    fn malformed_section_size_is_skipped() {
        let bytes = build_cstring_macho(0x2000, Some(0x1_0000));
        let img = Image::load(&bytes).unwrap();
        assert!(img.strings.is_empty(), "got {:?}", img.strings.len());
    }
}
