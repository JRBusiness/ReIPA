use crate::{Error, Result};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub fn at(buf: &'a [u8], pos: usize) -> Result<Reader<'a>> {
        if pos > buf.len() {
            return Err(Error::Eof(pos));
        }
        Ok(Reader { buf, pos })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.buf.len() {
            return Err(Error::Eof(pos));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.pos;
        let end = start.checked_add(n).ok_or(Error::Eof(start))?;
        if end > self.buf.len() {
            return Err(Error::Eof(start));
        }
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_fixed_str(&mut self, n: usize) -> Result<String> {
        let b = self.read_bytes(n)?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        Ok(String::from_utf8_lossy(&b[..end]).into_owned())
    }

    pub fn read_uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            if shift < 64 {
                result |= ((byte & 0x7f) as u64) << shift;
            }
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err(Error::Malformed("uleb128 too long"));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_ints() {
        let mut r = Reader::new(&[0x01, 0x00, 0x00, 0x00, 0xff, 0xff]);
        assert_eq!(r.read_u32().unwrap(), 1);
        assert_eq!(r.read_u16().unwrap(), 0xffff);
    }

    #[test]
    fn reads_big_endian_u32() {
        let mut r = Reader::new(&[0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(r.read_u32_be().unwrap(), 0xcafebabe);
    }

    #[test]
    fn oob_read_returns_eof_not_panic() {
        let mut r = Reader::new(&[0x00, 0x01]);
        assert_eq!(r.read_u32(), Err(Error::Eof(0)));
    }

    #[test]
    fn fixed_str_trims_nul() {
        let mut r = Reader::new(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(r.read_fixed_str(16).unwrap(), "__TEXT");
    }

    #[test]
    fn uleb128_multibyte() {
        let mut r = Reader::new(&[0xE5, 0x8E, 0x26]);
        assert_eq!(r.read_uleb128().unwrap(), 624485);
    }
}
