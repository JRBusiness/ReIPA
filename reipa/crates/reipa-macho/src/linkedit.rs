use crate::reader::Reader;
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct Encryption {
    pub cryptid: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
}

pub fn parse_encryption(body: &[u8]) -> Result<Encryption> {
    let mut r = Reader::new(body);
    let cryptoff = r.read_u32()?;
    let cryptsize = r.read_u32()?;
    let cryptid = r.read_u32()?;
    Ok(Encryption {
        cryptid,
        cryptoff,
        cryptsize,
    })
}

pub fn parse_uuid(body: &[u8]) -> Result<[u8; 16]> {
    let mut r = Reader::new(body);
    let b = r.read_bytes(16)?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(b);
    Ok(uuid)
}

pub fn parse_function_starts(file: &[u8], body: &[u8], text_vmaddr: u64) -> Result<Vec<u64>> {
    let mut r = Reader::new(body);
    let dataoff = r.read_u32()? as usize;
    let datasize = r.read_u32()? as usize;
    let end = dataoff
        .checked_add(datasize)
        .ok_or(crate::Error::Eof(dataoff))?;
    if end > file.len() {
        return Err(crate::Error::Eof(dataoff));
    }
    let mut dr = Reader::at(file, dataoff)?;
    let mut addr = text_vmaddr;
    let mut out = Vec::new();
    while dr.pos() < end {
        let delta = dr.read_uleb128()?;
        if delta == 0 {
            break;
        }
        addr = addr.wrapping_add(delta);
        out.push(addr);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linkedit_body(dataoff: u32, datasize: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&dataoff.to_le_bytes());
        b.extend_from_slice(&datasize.to_le_bytes());
        b
    }

    #[test]
    fn function_starts_accumulates_deltas_and_stops_at_zero() {
        let mut file = vec![0u8; 8];
        let dataoff = file.len() as u32;
        file.extend_from_slice(&[0x10, 0x20, 0x00]);
        let body = linkedit_body(dataoff, 3);
        let starts = parse_function_starts(&file, &body, 0x4000).unwrap();
        assert_eq!(starts, vec![0x4010, 0x4030]);
    }

    #[test]
    fn function_starts_decodes_multibyte_uleb128() {
        let mut file = vec![0u8; 4];
        let dataoff = file.len() as u32;
        file.extend_from_slice(&[0x80, 0x01, 0x00]);
        let body = linkedit_body(dataoff, 3);
        let starts = parse_function_starts(&file, &body, 0x4000).unwrap();
        assert_eq!(starts, vec![0x4080]);
    }

    #[test]
    fn function_starts_out_of_bounds_dataoff_errors() {
        let file = vec![0u8; 8];
        let body = linkedit_body(1000, 10);
        assert!(parse_function_starts(&file, &body, 0x4000).is_err());
    }

    #[test]
    fn encryption_and_uuid_parse_fields() {
        let mut enc = Vec::new();
        enc.extend_from_slice(&0x4000u32.to_le_bytes());
        enc.extend_from_slice(&0x1000u32.to_le_bytes());
        enc.extend_from_slice(&1u32.to_le_bytes());
        enc.extend_from_slice(&0u32.to_le_bytes());
        let e = parse_encryption(&enc).unwrap();
        assert_eq!(e.cryptid, 1);
        assert_eq!(e.cryptoff, 0x4000);
        assert_eq!(e.cryptsize, 0x1000);

        let uuid = parse_uuid(&[0xAB; 16]).unwrap();
        assert_eq!(uuid, [0xAB; 16]);
    }
}
