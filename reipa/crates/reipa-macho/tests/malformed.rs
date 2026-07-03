use reipa_macho::MachOImage;

#[test]
fn never_panics_on_truncation() {
    use reipa_macho::consts::*;
    let mut base = Vec::new();
    base.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    base.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    base.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    base.extend_from_slice(&2u32.to_le_bytes());
    base.extend_from_slice(&50u32.to_le_bytes());
    base.extend_from_slice(&0x1000u32.to_le_bytes());
    base.extend_from_slice(&0u32.to_le_bytes());
    base.extend_from_slice(&0u32.to_le_bytes());

    for len in 0..base.len() {
        let _ = MachOImage::parse(&base[..len]);
    }
    for seed in 0u8..64 {
        let junk: Vec<u8> = (0..256)
            .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(7))
            .collect();
        let _ = MachOImage::parse(&junk);
    }
}
