use crate::reader::Reader;
use crate::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct Section {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Segment {
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub sections: Vec<Section>,
}

pub fn parse_segment(body: &[u8]) -> Result<Segment> {
    let mut r = Reader::new(body);
    let segname = r.read_fixed_str(16)?;
    let vmaddr = r.read_u64()?;
    let vmsize = r.read_u64()?;
    let fileoff = r.read_u64()?;
    let filesize = r.read_u64()?;
    let _maxprot = r.read_u32()?;
    let _initprot = r.read_u32()?;
    let nsects = r.read_u32()?;
    let _flags = r.read_u32()?;

    let mut sections = Vec::new();
    for _ in 0..nsects {
        let sectname = r.read_fixed_str(16)?;
        let sect_segname = r.read_fixed_str(16)?;
        let addr = r.read_u64()?;
        let size = r.read_u64()?;
        let offset = r.read_u32()?;
        let _align = r.read_u32()?;
        let _reloff = r.read_u32()?;
        let _nreloc = r.read_u32()?;
        let flags = r.read_u32()?;
        let _r1 = r.read_u32()?;
        let _r2 = r.read_u32()?;
        let _r3 = r.read_u32()?;
        sections.push(Section {
            sectname,
            segname: sect_segname,
            addr,
            size,
            offset,
            flags,
        });
    }
    Ok(Segment { segname, vmaddr, vmsize, fileoff, filesize, sections })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg_body_one_section() -> Vec<u8> {
        let mut b = Vec::new();
        let mut segname = b"__TEXT".to_vec();
        segname.resize(16, 0);
        b.extend_from_slice(&segname);
        b.extend_from_slice(&0x1000u64.to_le_bytes());
        b.extend_from_slice(&0x4000u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0x4000u64.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        let mut sectname = b"__text".to_vec();
        sectname.resize(16, 0);
        b.extend_from_slice(&sectname);
        b.extend_from_slice(&segname);
        b.extend_from_slice(&0x1000u64.to_le_bytes());
        b.extend_from_slice(&0x400u64.to_le_bytes());
        b.extend_from_slice(&0x1000u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0x80000400u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    #[test]
    fn parses_segment_and_section() {
        let body = seg_body_one_section();
        let seg = parse_segment(&body).unwrap();
        assert_eq!(seg.segname, "__TEXT");
        assert_eq!(seg.vmaddr, 0x1000);
        assert_eq!(seg.sections.len(), 1);
        assert_eq!(seg.sections[0].sectname, "__text");
        assert_eq!(seg.sections[0].offset, 0x1000);
    }

    #[test]
    fn huge_nsects_with_tiny_body_errors_fast() {
        let mut b = Vec::new();
        let mut segname = b"__DATA".to_vec();
        segname.resize(16, 0);
        b.extend_from_slice(&segname);
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_segment(&b).is_err());
    }
}
