//! file handling support for subunit V2

use crate::serialize::Serializable;

/// A file event in Subunit V2 has a name, optional content, and an optional end of file marker. The files MIME type can
/// also be specified. The wire format can represent these all as separate concepts, which leads to a little friction in
/// the language bindings.
///
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L329)
#[derive(Debug, Default, Clone, PartialEq)]
pub struct File {
    /// Optional MIME type.
    pub mime_type: Option<String>,
    /// Optional File name and content
    pub file: Option<(String, Vec<u8>)>,
    /// The end of file marker
    pub eof: bool,
}

impl Serializable for File {
    fn wire_size(&self) -> crate::GenResult<crate::types::number::SubunitNumber> {
        self.mime_type.wire_size()? + self.file.wire_size()?
        // EOF is serialised as a flag
    }

    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> crate::GenResult<()> {
        self.mime_type.serialize(writer)?;
        self.file.serialize(writer)?;
        Ok(())
    }
}

// TODO: move the file handling here, after Reader without hashing is usable.
// impl Deserializable for File {
//     fn required_bytes(_bytes: &[u8]) -> crate::GenResult<usize> {
//         unimplemented!("File::required_bytes")
//     }

//     fn deserialize(bytes: &[u8]) -> crate::GenResult<(File, usize)> {
//         unimplemented!("File::deserialize")
//     }
// }
