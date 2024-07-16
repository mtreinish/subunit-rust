//! Support for streams of subunit events.

use crate::{
    constants::V2_SIGNATURE, deserialize::Deserializable, types::event::Event, Error, GenError,
    GenResult,
};

/// Newtype to hold the implementation of a UTF8 variable length encoding. Not 'char' because surrogates are included.
/// Perhaps it will be hidden in future.
#[derive(Debug)]
pub struct UTF8VariableLength {
    pub bytes: Vec<u8>,
}

impl Deserializable for UTF8VariableLength {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        if bytes.is_empty() {
            return Ok(1);
        }
        // Single octet codepoint
        if bytes[0] & 0b10000000 == 0 {
            return Ok(1);
        }
        // Continuation byte at start of sequence
        if bytes[0] & 0b01000000 == 0 {
            return Err(Error::InvalidUTF8Sequence.into());
        }
        // Two octet codepoint
        if bytes[0] & 0b00100000 == 0 {
            return Ok(2);
        }
        // Three octet codepoint
        if bytes[0] & 0b00010000 == 0 {
            return Ok(3);
        }
        // Four octet codepoint
        if bytes[0] & 0b00001000 == 0 {
            return Ok(4);
        }
        // 5 leading 1's? What is 5 leading 1's?
        Err(Error::InvalidUTF8Sequence.into())
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Self, usize)> {
        let length = Self::required_bytes(bytes)?;
        Ok((
            UTF8VariableLength {
                bytes: bytes[..length].to_vec(),
            },
            length,
        ))
    }
}

/// Items in a subunit stream
#[derive(Debug)]
pub enum ScannedItem {
    /// Non-event data following the UTF8 variable length encoding. May not actually be valid UTF8.
    UTF8chars(UTF8VariableLength),
    /// A subunit event
    Event(Event),
    /// Bytes that that are neither UTF8 variable-length encoded nor a valid
    /// Subunit packet. Could be: interrupted bytes of either at the end of a
    /// stream, striped and corrupted data, or a Subunit packet with a bad checksum
    Unknown(Vec<u8>, GenError),
}

impl Deserializable for ScannedItem {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        Event::required_bytes(bytes).or_else(|_| UTF8VariableLength::required_bytes(bytes))
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Self, usize)> {
        // TODO: likely the unknown case is not handled thoroughly enough: we should fuzz this.
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes.into());
        }
        if bytes[0] == V2_SIGNATURE {
            match Event::deserialize(bytes) {
                Ok((event, used)) => Ok((ScannedItem::Event(event), used)),
                Err(e) => {
                    // In the normal codepath, hitting deserialize implies required_bytes succeeded.
                    let packet_length = Event::required_bytes(bytes)?;
                    // Probably a corrupt packet, but we can't know how much is corrupt.
                    Ok((
                        ScannedItem::Unknown(bytes[..packet_length].to_vec(), e),
                        packet_length,
                    ))
                }
            }
        } else {
            match UTF8VariableLength::required_bytes(bytes) {
                Ok(required) => {
                    let (utf8, used) = UTF8VariableLength::deserialize(&bytes[..required])?;
                    Ok((ScannedItem::UTF8chars(utf8), used))
                }
                Err(e) => {
                    // How much is corrupt / unknowable isn't known, so take one byte
                    Ok((ScannedItem::Unknown(bytes[..1].to_vec(), e), 1))
                }
            }
        }
    }
}
