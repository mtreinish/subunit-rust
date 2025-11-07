//! Support for streams of subunit events.

use crate::{
    constants::V2_SIGNATURE, deserialize::Deserializable, types::event::Event, Error, GenError,
    GenResult,
};

/// Items in a subunit stream
#[derive(Debug)]
pub enum ScannedItem {
    /// Non-event data - raw bytes that are not part of a subunit event.
    /// This data is interleaved with the subunit stream (e.g., stdout/stderr).
    Bytes(Vec<u8>),
    /// A subunit event
    Event(Event),
    /// Bytes that that are neither valid non-event data nor a valid
    /// Subunit packet. Could be: interrupted bytes of either at the end of a
    /// stream, striped and corrupted data, or a Subunit packet with a bad checksum
    Unknown(Vec<u8>, GenError),
}

impl Deserializable for ScannedItem {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        // If it's an event, return the event's required bytes
        // Otherwise, just consume 1 byte at a time for non-event data
        Event::required_bytes(bytes).or(Ok(1))
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
            // Non-event data - just forward the byte as-is
            Ok((ScannedItem::Bytes(vec![bytes[0]]), 1))
        }
    }
}
