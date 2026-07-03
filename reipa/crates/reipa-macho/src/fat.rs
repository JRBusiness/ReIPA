use crate::consts::*;
use crate::reader::Reader;
use crate::{Error, Result};

pub struct Slice<'a> {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub data: &'a [u8],
}

fn is_arm64(cputype: u32) -> bool {
    cputype == CPU_TYPE_ARM64
}

pub fn select_arm64_slice(buf: &[u8]) -> Result<Slice<'_>> {
    let mut r = Reader::new(buf);
    let magic = r.read_u32_be()?;
    match magic {
        FAT_MAGIC | FAT_MAGIC_64 => {
            let is64 = magic == FAT_MAGIC_64;
            let nfat = r.read_u32_be()?;
            for _ in 0..nfat {
                let cputype = r.read_u32_be()?;
                let cpusubtype = r.read_u32_be()?;
                let (offset, size) = if is64 {
                    let off = r.read_u32_be()? as u64;
                    let _ = off;
                    return Err(Error::Malformed("fat64 unsupported in v1"));
                } else {
                    let off = r.read_u32_be()? as usize;
                    let size = r.read_u32_be()? as usize;
                    let _align = r.read_u32_be()?;
                    (off, size)
                };
                if is_arm64(cputype) {
                    let end = offset.checked_add(size).ok_or(Error::Eof(offset))?;
                    if end > buf.len() {
                        return Err(Error::Eof(offset));
                    }
                    return Ok(Slice {
                        cputype,
                        cpusubtype,
                        data: &buf[offset..end],
                    });
                }
            }
            Err(Error::NoArm64Slice)
        }
        _ => {
            let mut r2 = Reader::new(buf);
            let magic_le = r2.read_u32()?;
            if magic_le != MH_MAGIC_64 {
                return Err(Error::BadMagic(magic_le));
            }
            let cputype = r2.read_u32()?;
            let cpusubtype = r2.read_u32()?;
            if !is_arm64(cputype) {
                return Err(Error::NoArm64Slice);
            }
            Ok(Slice {
                cputype,
                cpusubtype,
                data: buf,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin_arm64_header() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        v.resize(32, 0);
        v
    }

    #[test]
    fn thin_binary_returns_whole_buffer() {
        let bytes = thin_arm64_header();
        let s = select_arm64_slice(&bytes).unwrap();
        assert_eq!(s.cputype, CPU_TYPE_ARM64);
        assert_eq!(s.data.len(), bytes.len());
    }

    #[test]
    fn fat_binary_selects_arm64_slice() {
        let payload = thin_arm64_header();
        let payload_offset = 4 + 4 + 20;
        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
        v.extend_from_slice(&(payload_offset as u32).to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&payload);
        let s = select_arm64_slice(&v).unwrap();
        assert_eq!(s.data, payload.as_slice());
    }

    #[test]
    fn non_arm64_thin_binary_errors() {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&0x0100_0007u32.to_le_bytes());
        v.resize(32, 0);
        assert_eq!(select_arm64_slice(&v).err(), Some(Error::NoArm64Slice));
    }
}
