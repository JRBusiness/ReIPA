use crate::consts::*;
use crate::fat::Slice;
use crate::reader::Reader;
use crate::{Error, Result};

#[derive(Debug, PartialEq, Eq)]
pub struct MachHeader {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub flags: u32,
}

pub struct LoadCommand<'a> {
    pub cmd: u32,
    pub body: &'a [u8],
}

const MACH_HEADER_64_SIZE: usize = 32;

pub fn parse_header(slice: &Slice) -> Result<MachHeader> {
    let mut r = Reader::new(slice.data);
    let magic = r.read_u32()?;
    if magic != MH_MAGIC_64 {
        return Err(Error::BadMagic(magic));
    }
    let cputype = r.read_u32()?;
    let cpusubtype = r.read_u32()?;
    let filetype = r.read_u32()?;
    let ncmds = r.read_u32()?;
    let _sizeofcmds = r.read_u32()?;
    let flags = r.read_u32()?;
    let _reserved = r.read_u32()?;
    Ok(MachHeader { cputype, cpusubtype, filetype, ncmds, flags })
}

pub fn load_commands<'a>(slice: &'a Slice) -> Result<Vec<LoadCommand<'a>>> {
    let header = parse_header(slice)?;
    let mut out = Vec::new();
    let mut offset = MACH_HEADER_64_SIZE;
    for _ in 0..header.ncmds {
        let mut r = Reader::at(slice.data, offset)?;
        let cmd = r.read_u32()?;
        let cmdsize = r.read_u32()? as usize;
        if cmdsize < 8 {
            return Err(Error::Malformed("cmdsize < 8"));
        }
        let body_len = cmdsize - 8;
        let body = r.read_bytes(body_len)?;
        out.push(LoadCommand { cmd, body });
        offset = offset.checked_add(cmdsize).ok_or(Error::Eof(offset))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice_with(cmds: &[(u32, Vec<u8>)]) -> Vec<u8> {
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
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&(cmds.len() as u32).to_le_bytes());
        v.extend_from_slice(&(lc.len() as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&lc);
        v
    }

    #[test]
    fn parses_header_fields() {
        let bytes = slice_with(&[]);
        let s = Slice { cputype: CPU_TYPE_ARM64, cpusubtype: 0, data: &bytes };
        let h = parse_header(&s).unwrap();
        assert_eq!(h.cputype, CPU_TYPE_ARM64);
        assert_eq!(h.filetype, 2);
        assert_eq!(h.ncmds, 0);
    }

    #[test]
    fn iterates_load_commands() {
        let bytes = slice_with(&[(LC_UUID, vec![0xaa; 16]), (LC_SYMTAB, vec![0xbb; 16])]);
        let s = Slice { cputype: CPU_TYPE_ARM64, cpusubtype: 0, data: &bytes };
        let cmds = load_commands(&s).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].cmd, LC_UUID);
        assert_eq!(cmds[0].body, &[0xaa; 16]);
        assert_eq!(cmds[1].cmd, LC_SYMTAB);
    }

    #[test]
    fn truncated_load_command_errors() {
        let mut bytes = slice_with(&[(LC_UUID, vec![0xaa; 16])]);
        bytes.truncate(bytes.len() - 4);
        let s = Slice { cputype: CPU_TYPE_ARM64, cpusubtype: 0, data: &bytes };
        assert!(load_commands(&s).is_err());
    }

    #[test]
    fn huge_ncmds_with_tiny_buffer_errors_fast() {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        v.extend_from_slice(&0x1000u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        let s = Slice { cputype: CPU_TYPE_ARM64, cpusubtype: 0, data: &v };
        assert!(load_commands(&s).is_err());
    }
}
