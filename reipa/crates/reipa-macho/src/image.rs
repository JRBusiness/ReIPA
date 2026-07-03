use crate::chained_fixups::{parse_chained_fixups, ChainedFixup};
use crate::consts::*;
use crate::dyld_info::{parse_dyld_info_binds, Bind};
use crate::fat::select_arm64_slice;
use crate::header::load_commands;
use crate::linkedit::{parse_encryption, parse_function_starts, parse_uuid, Encryption};
use crate::reader::Reader;
use crate::segment::{parse_segment, Section, Segment};
use crate::symtab::{parse_symtab, Symbol};
use crate::Result;

#[derive(Debug)]
pub struct MachOImage {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub uuid: Option<[u8; 16]>,
    pub encryption: Option<Encryption>,
    pub function_starts: Vec<u64>,
    pub has_chained_fixups: bool,
    pub binds: Vec<Bind>,
    pub chained_fixups: Vec<ChainedFixup>,
}

impl MachOImage {
    pub fn parse(buf: &[u8]) -> Result<MachOImage> {
        let slice = select_arm64_slice(buf)?;
        let cmds = load_commands(&slice)?;

        let mut segments = Vec::new();
        let mut symbols = Vec::new();
        let mut uuid = None;
        let mut encryption = None;
        let mut has_chained_fixups = false;

        for lc in &cmds {
            match lc.cmd {
                LC_SEGMENT_64 => {
                    if let Ok(seg) = parse_segment(lc.body) {
                        segments.push(seg);
                    }
                }
                LC_SYMTAB => {
                    if let Ok(mut s) = parse_symtab(slice.data, lc.body) {
                        symbols.append(&mut s);
                    }
                }
                LC_UUID => {
                    uuid = parse_uuid(lc.body).ok();
                }
                LC_ENCRYPTION_INFO_64 => {
                    encryption = parse_encryption(lc.body).ok();
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    has_chained_fixups = true;
                }
                _ => {}
            }
        }

        let text_vmaddr = segments
            .iter()
            .find(|s| s.segname == "__TEXT")
            .map(|s| s.vmaddr)
            .unwrap_or(0);

        let mut function_starts = Vec::new();
        let mut binds = Vec::new();
        let mut chained_fixups = Vec::new();
        for lc in &cmds {
            if lc.cmd == LC_FUNCTION_STARTS {
                if let Ok(fs) = parse_function_starts(slice.data, lc.body, text_vmaddr) {
                    function_starts = fs;
                }
            }
            if lc.cmd == LC_DYLD_INFO || lc.cmd == LC_DYLD_INFO_ONLY {
                binds = parse_dyld_info_binds(slice.data, lc.body, &segments);
            }
            if lc.cmd == LC_DYLD_CHAINED_FIXUPS {
                chained_fixups =
                    parse_chained_fixups(slice.data, lc.body, &segments, text_vmaddr);
            }
        }

        let header = crate::header::parse_header(&slice)?;
        Ok(MachOImage {
            cputype: slice.cputype,
            cpusubtype: slice.cpusubtype,
            filetype: header.filetype,
            segments,
            symbols,
            uuid,
            encryption,
            function_starts,
            has_chained_fixups,
            binds,
            chained_fixups,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(&self.encryption, Some(e) if e.cryptid != 0)
    }

    pub fn text_vmaddr(&self) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| s.segname == "__TEXT")
            .map(|s| s.vmaddr)
    }

    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.segments
            .iter()
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == name)
    }

    pub fn vmaddr_to_offset(&self, vmaddr: u64) -> Option<usize> {
        for seg in &self.segments {
            let seg_end = seg.vmaddr.checked_add(seg.vmsize)?;
            if vmaddr >= seg.vmaddr && vmaddr < seg_end {
                let delta = vmaddr - seg.vmaddr;
                if delta < seg.filesize {
                    return usize::try_from(seg.fileoff.checked_add(delta)?).ok();
                }
                return None;
            }
        }
        None
    }

    pub fn read_u64_at(&self, data: &[u8], offset: usize) -> Option<u64> {
        Reader::at(data, offset).ok()?.read_u64().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment_body() -> Vec<u8> {
        let mut b = Vec::new();
        let mut name = b"__TEXT".to_vec();
        name.resize(16, 0);
        b.extend_from_slice(&name);
        b.extend_from_slice(&0x1000u64.to_le_bytes());
        b.extend_from_slice(&0x4000u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0x4000u64.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    fn build(cmds: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut lc = Vec::new();
        for (cmd, body) in cmds {
            let raw = 8 + body.len();
            let cmdsize = (raw + 7) & !7;
            lc.extend_from_slice(&cmd.to_le_bytes());
            lc.extend_from_slice(&(cmdsize as u32).to_le_bytes());
            lc.extend_from_slice(body);
            lc.resize(lc.len() + (cmdsize - raw), 0);
        }
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64E.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&(cmds.len() as u32).to_le_bytes());
        v.extend_from_slice(&(lc.len() as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&lc);
        v
    }

    #[test]
    fn parses_full_image_with_encryption_flag() {
        let mut enc = Vec::new();
        enc.extend_from_slice(&0x4000u32.to_le_bytes());
        enc.extend_from_slice(&0x1000u32.to_le_bytes());
        enc.extend_from_slice(&1u32.to_le_bytes());
        enc.extend_from_slice(&0u32.to_le_bytes());
        let bytes = build(&[
            (LC_SEGMENT_64, segment_body()),
            (LC_UUID, vec![0x11; 16]),
            (LC_ENCRYPTION_INFO_64, enc),
        ]);
        let img = MachOImage::parse(&bytes).unwrap();
        assert_eq!(img.cpusubtype, CPU_SUBTYPE_ARM64E);
        assert_eq!(img.segments.len(), 1);
        assert_eq!(img.text_vmaddr(), Some(0x1000));
        assert_eq!(img.uuid, Some([0x11; 16]));
        assert!(img.is_encrypted());
    }

    #[test]
    fn unencrypted_when_no_command() {
        let bytes = build(&[(LC_SEGMENT_64, segment_body())]);
        let img = MachOImage::parse(&bytes).unwrap();
        assert!(!img.is_encrypted());
    }

    #[test]
    fn encryption_command_present_but_cryptid_zero_is_not_encrypted() {
        let mut enc = Vec::new();
        enc.extend_from_slice(&0x4000u32.to_le_bytes());
        enc.extend_from_slice(&0x1000u32.to_le_bytes());
        enc.extend_from_slice(&0u32.to_le_bytes());
        enc.extend_from_slice(&0u32.to_le_bytes());
        let bytes = build(&[
            (LC_SEGMENT_64, segment_body()),
            (LC_ENCRYPTION_INFO_64, enc),
        ]);
        let img = MachOImage::parse(&bytes).unwrap();
        assert!(img.encryption.is_some());
        assert!(!img.is_encrypted());
    }

    #[test]
    fn vmaddr_to_offset_no_overflow_on_huge_fileoff() {
        let mut body = Vec::new();
        let mut name = b"__DATA".to_vec();
        name.resize(16, 0);
        body.extend_from_slice(&name);
        body.extend_from_slice(&0x1000u64.to_le_bytes());
        body.extend_from_slice(&0x2000u64.to_le_bytes());
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        body.extend_from_slice(&0x2000u64.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let bytes = build(&[(LC_SEGMENT_64, body)]);
        let img = MachOImage::parse(&bytes).unwrap();
        assert_eq!(img.vmaddr_to_offset(0x1100), None);
    }

    #[test]
    fn vmaddr_to_offset_maps_within_segment_and_rejects_outside() {
        let bytes = build(&[(LC_SEGMENT_64, segment_body())]);
        let img = MachOImage::parse(&bytes).unwrap();
        assert_eq!(img.vmaddr_to_offset(0x1000), Some(0));
        assert_eq!(img.vmaddr_to_offset(0x1234), Some(0x234));
        assert_eq!(img.vmaddr_to_offset(0x0), None);
        assert_eq!(img.vmaddr_to_offset(0x9000), None);
        assert!(img.section_by_name("__nope").is_none());
    }
}
