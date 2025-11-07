//! Synchronous I/O module

use std::{collections::VecDeque, io::Read};

use crate::{deserialize::Deserializable, types::stream::ScannedItem, Error, GenResult};

/// Ask a struct to write itself to some impl Write
pub trait WriteInto {
    /// Write the struct to the writer
    fn write_into(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()>;
}

/// Look for subunit events in an input stream.
#[derive(Default, Debug)]
pub struct Scanner<R> {
    buffer: VecDeque<u8>,
    reader: R,
}

/// Iterate over a Readable, yielding the contents as `ScannedItems`.
pub fn iter_stream<R: Read>(reader: R) -> impl Iterator<Item = GenResult<ScannedItem>> {
    // Maximum buffer needed to process subunit packets is 4MB
    let buffer = VecDeque::<u8>::with_capacity(4 * 1024 * 1024);
    Scanner { buffer, reader }
}

impl<R> Iterator for Scanner<R>
where
    R: Read,
{
    type Item = GenResult<ScannedItem>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut required_bytes = {
            let buf = self.buffer.make_contiguous();
            match ScannedItem::required_bytes(buf) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            }
        };
        while self.buffer.len() < required_bytes {
            let mut read_buffer = [0u8; 8192];
            match self.reader.read(&mut read_buffer) {
                Ok(0) => {
                    if self.buffer.is_empty() {
                        return None;
                    }
                    // By definition, we have a partial packet or partial byte
                    return Some(Ok(ScannedItem::Unknown(
                        self.buffer.drain(..).collect(),
                        Error::NotEnoughBytes.into(),
                    )));
                }
                Ok(bytes_read) => {
                    // Might not be enough read yet
                    self.buffer.extend(read_buffer[..bytes_read].iter());
                }
                Err(e) => return Some(Err(e.into())),
            }
            let buf = self.buffer.make_contiguous();
            required_bytes = match ScannedItem::required_bytes(buf) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
        }

        // Now we have enough data to do something with it.

        let buf = self.buffer.make_contiguous();
        match ScannedItem::deserialize(buf) {
            Ok((ScannedItem::Event(event), used)) => {
                self.buffer.drain(..used);
                Some(Ok(ScannedItem::Event(event)))
            }
            Ok((ScannedItem::Bytes(_), _)) => {
                // Collect all consecutive non-event bytes into a single item
                let mut bytes = Vec::new();
                while let Some(&byte) = self.buffer.front() {
                    if byte == crate::constants::V2_SIGNATURE {
                        break;
                    }
                    bytes.push(self.buffer.pop_front().unwrap());
                }
                Some(Ok(ScannedItem::Bytes(bytes)))
            }
            Ok((ScannedItem::Unknown(data, e), _)) => Some(Ok(ScannedItem::Unknown(data, e))),
            Err(e) => {
                // We know from the loop above that we had enough bytes, and this is not IO: some form of junk.
                // We have an invalid char or failed crc32 or similar.
                Some(Ok(ScannedItem::Unknown(
                    self.buffer.drain(..required_bytes).collect(),
                    e,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use chrono::{TimeZone, Utc};

    use crate::{
        io::sync,
        serialize::Serializable,
        types::{event::Event, stream::ScannedItem, teststatus::TestStatus},
    };

    #[test]
    fn test_write_full_test_event_with_file_content() {
        let event = Event::new(TestStatus::InProgress)
            .test_id("A_test_id")
            .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap())
            .unwrap()
            .tag("tag_a")
            .tag("tag_b")
            .mime_type("text/plain;charset=utf8")
            .file_content("stdout:''", b"stdout content")
            .build();
        let event_a = Event::new(TestStatus::Failed)
            .test_id("A_test_id")
            .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 12, 1).unwrap())
            .unwrap()
            .tag("tag_a")
            .tag("tag_b")
            .build();

        let mut buffer = event.to_vec().unwrap();
        event_a.serialize(&mut buffer).unwrap();

        for (parsed_event, event) in
            sync::iter_stream(Cursor::new(&buffer)).zip([event, event_a].iter())
        {
            let parsed_event = parsed_event.unwrap();
            let ScannedItem::Event(parsed_event) = parsed_event else {
                panic!("Expected event, got {:?}", parsed_event);
            };
            assert_eq!(*event, parsed_event);
        }
    }

    #[test]
    fn test_stream_with_invalid_utf8() {
        // Test that we can parse a stream with invalid UTF-8 bytes interleaved
        let event = Event::new(TestStatus::Success).test_id("test").build();

        let mut buffer = Vec::new();
        // Add some invalid UTF-8 bytes (0xFF is not valid UTF-8 start byte)
        buffer.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        // Add a valid event
        event.serialize(&mut buffer).unwrap();
        // Add more invalid UTF-8
        buffer.extend_from_slice(&[0x80, 0x81]);

        let items: Vec<_> = sync::iter_stream(Cursor::new(&buffer))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // We should get: 1 Bytes item (with 3 bytes), 1 Event, 1 Bytes item (with 2 bytes)
        assert_eq!(items.len(), 3);
        match &items[0] {
            ScannedItem::Bytes(bytes) => assert_eq!(bytes, &[0xFF, 0xFE, 0xFD]),
            _ => panic!("Expected Bytes, got {:?}", items[0]),
        }
        assert!(matches!(items[1], ScannedItem::Event(_)));
        match &items[2] {
            ScannedItem::Bytes(bytes) => assert_eq!(bytes, &[0x80, 0x81]),
            _ => panic!("Expected Bytes, got {:?}", items[2]),
        }
    }
}
