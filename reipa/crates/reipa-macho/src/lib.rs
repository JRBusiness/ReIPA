pub mod chained_fixups;
pub mod consts;
pub mod dyld_info;
pub mod fat;
pub mod header;
pub mod image;
pub mod linkedit;
pub mod reader;
pub mod segment;
pub mod symtab;

pub use image::MachOImage;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unexpected end of data at offset {0}")]
    Eof(usize),
    #[error("bad magic: 0x{0:08x}")]
    BadMagic(u32),
    #[error("no arm64/arm64e slice found")]
    NoArm64Slice,
    #[error("malformed structure: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;
