use reipa_macho::consts::*;

pub struct MachoBuilder {
    cputype: u32,
    cpusubtype: u32,
    load_commands: Vec<(u32, Vec<u8>)>,
}

impl MachoBuilder {
    pub fn new_thin_arm64() -> MachoBuilder {
        MachoBuilder {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            load_commands: Vec::new(),
        }
    }

    pub fn add_load_command(&mut self, cmd: u32, body: &[u8]) -> &mut Self {
        self.load_commands.push((cmd, body.to_vec()));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut lc_bytes = Vec::new();
        for (cmd, body) in &self.load_commands {
            let raw = 8 + body.len();
            let cmdsize = (raw + 7) & !7;
            lc_bytes.extend_from_slice(&cmd.to_le_bytes());
            lc_bytes.extend_from_slice(&(cmdsize as u32).to_le_bytes());
            lc_bytes.extend_from_slice(body);
            lc_bytes.resize(lc_bytes.len() + (cmdsize - raw), 0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        out.extend_from_slice(&self.cputype.to_le_bytes());
        out.extend_from_slice(&self.cpusubtype.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&(self.load_commands.len() as u32).to_le_bytes());
        out.extend_from_slice(&(lc_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&lc_bytes);
        out
    }
}

#[test]
fn builder_emits_parseable_header_size() {
    let bytes = MachoBuilder::new_thin_arm64().build();
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes[0..4], &MH_MAGIC_64.to_le_bytes());
}
