use crate::reader::Reader;
use crate::{Error, Result};

#[derive(Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub n_type: u8,
    pub n_sect: u8,
}

fn read_c_str(file: &[u8], stroff: usize, strsize: usize, n_strx: u32) -> Result<String> {
    let start = stroff
        .checked_add(n_strx as usize)
        .ok_or(Error::Eof(stroff))?;
    let table_end = stroff.checked_add(strsize).ok_or(Error::Eof(stroff))?;
    if start > table_end || table_end > file.len() {
        return Err(Error::Malformed("string index out of range"));
    }
    let bytes = &file[start..table_end];
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

pub fn parse_symtab(file: &[u8], body: &[u8]) -> Result<Vec<Symbol>> {
    let mut r = Reader::new(body);
    let symoff = r.read_u32()? as usize;
    let nsyms = r.read_u32()? as usize;
    let stroff = r.read_u32()? as usize;
    let strsize = r.read_u32()? as usize;

    let mut out = Vec::new();
    let mut sr = Reader::at(file, symoff)?;
    for _ in 0..nsyms {
        let n_strx = sr.read_u32()?;
        let n_type = sr.read_u8()?;
        let n_sect = sr.read_u8()?;
        let _n_desc = sr.read_u16()?;
        let n_value = sr.read_u64()?;
        let name = read_c_str(file, stroff, strsize, n_strx)?;
        out.push(Symbol {
            name,
            value: n_value,
            n_type,
            n_sect,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_symbol() {
        let strtab = b"\0_main\0";
        let mut file = Vec::new();
        let stroff = 0usize;
        file.extend_from_slice(strtab);
        while file.len() % 4 != 0 {
            file.push(0);
        }
        let symoff = file.len();
        file.extend_from_slice(&1u32.to_le_bytes());
        file.push(0x0f);
        file.push(0x01);
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0x4000u64.to_le_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&(symoff as u32).to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&(stroff as u32).to_le_bytes());
        body.extend_from_slice(&(strtab.len() as u32).to_le_bytes());

        let syms = parse_symtab(&file, &body).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "_main");
        assert_eq!(syms[0].value, 0x4000);
        assert_eq!(syms[0].n_type, 0x0f);
    }

    #[test]
    fn huge_nsyms_with_tiny_buffer_errors_fast() {
        let file = vec![0u8; 16];
        let mut body = Vec::new();
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_symtab(&file, &body).is_err());
    }
}
