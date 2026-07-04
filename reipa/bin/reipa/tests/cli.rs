use std::process::Command;

fn minimal_macho() -> Vec<u8> {
    use reipa_macho::consts::*;
    let mut seg = Vec::new();
    let mut name = b"__TEXT".to_vec();
    name.resize(16, 0);
    seg.extend_from_slice(&name);
    seg.extend_from_slice(&0x1000u64.to_le_bytes());
    seg.extend_from_slice(&0x4000u64.to_le_bytes());
    seg.extend_from_slice(&0u64.to_le_bytes());
    seg.extend_from_slice(&0x4000u64.to_le_bytes());
    seg.extend_from_slice(&5u32.to_le_bytes());
    seg.extend_from_slice(&5u32.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes());
    let cmdsize = 8 + seg.len();
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
    v
}

fn minimal_macho_encrypted() -> Vec<u8> {
    use reipa_macho::consts::*;
    let mut seg = Vec::new();
    let mut name = b"__TEXT".to_vec();
    name.resize(16, 0);
    seg.extend_from_slice(&name);
    seg.extend_from_slice(&0x1000u64.to_le_bytes());
    seg.extend_from_slice(&0x4000u64.to_le_bytes());
    seg.extend_from_slice(&0u64.to_le_bytes());
    seg.extend_from_slice(&0x4000u64.to_le_bytes());
    seg.extend_from_slice(&5u32.to_le_bytes());
    seg.extend_from_slice(&5u32.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes());
    seg.extend_from_slice(&0u32.to_le_bytes());
    let seg_cmdsize = 8 + seg.len();
    let mut enc = Vec::new();
    enc.extend_from_slice(&0x1000u32.to_le_bytes());
    enc.extend_from_slice(&0x3000u32.to_le_bytes());
    enc.extend_from_slice(&1u32.to_le_bytes());
    enc.extend_from_slice(&0u32.to_le_bytes());
    let enc_cmdsize = 8 + enc.len();

    let sizeofcmds = seg_cmdsize + enc_cmdsize;
    let mut v = Vec::new();
    v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    v.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    v.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    v.extend_from_slice(&(seg_cmdsize as u32).to_le_bytes());
    v.extend_from_slice(&seg);
    v.extend_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
    v.extend_from_slice(&(enc_cmdsize as u32).to_le_bytes());
    v.extend_from_slice(&enc);
    v
}

#[test]
fn verify_reports_unencrypted() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = std::path::Path::new(dir).join("reipa_test_min.macho");
    std::fs::write(&path, minimal_macho()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_reipa"))
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ENCRYPTED:  no"), "got: {stdout}");
    assert!(stdout.contains("arm64"));
}

#[test]
fn rejects_invalid_zip() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = std::path::Path::new(dir).join("reipa_test_fake.ipa");
    std::fs::write(&path, b"PK\x03\x04rest-of-zip").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_reipa"))
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a valid zip"), "got: {stderr}");
}

#[test]
fn accepts_ipa_archive() {
    use std::io::Write;
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = std::path::Path::new(dir).join("reipa_test.ipa");
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file("Payload/Foo.app/Info.plist", opts).unwrap();
        zw.write_all(b"plist").unwrap();
        zw.start_file("Payload/Foo.app/Foo", opts).unwrap();
        zw.write_all(&minimal_macho()).unwrap();
        zw.finish().unwrap();
    }
    std::fs::write(&path, &buf).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_reipa"))
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ENCRYPTED:  no"), "got: {stdout}");
    assert!(stdout.contains("arm64"));
}

#[test]
fn verify_reports_encrypted_with_guidance() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = std::path::Path::new(dir).join("reipa_test_encrypted.macho");
    std::fs::write(&path, minimal_macho_encrypted()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_reipa"))
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ENCRYPTED:  YES"), "got: {stdout}");
    assert!(stdout.contains("FairPlay"), "got: {stdout}");
}

fn objc_macho() -> Vec<u8> {
    use reipa_macho::consts::*;
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
        for _ in 0..7 {
            s.extend_from_slice(&0u32.to_le_bytes());
        }
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
fn objc_lists_selectors_and_classnames() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    let path = std::path::Path::new(dir).join("reipa_test_objc.macho");
    std::fs::write(&path, objc_macho()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_reipa"))
        .arg("objc")
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("selectors:    2"), "got: {stdout}");
    assert!(stdout.contains("dealloc"), "got: {stdout}");
    assert!(stdout.contains("Foo"), "got: {stdout}");
    assert!(stdout.contains("v16@0:8"), "got: {stdout}");
}
