//! Synchronous I/O module

use std::{collections::VecDeque, io::Read};

use crate::{deserialize::Deserializable, types::stream::ScannedItem, Error, GenResult};

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
        let buf = self.buffer.make_contiguous();
        let mut required_bytes = match ScannedItem::required_bytes(buf) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        while buf.len() < required_bytes {
            match self.reader.read(buf) {
                Ok(0) => {
                    if buf.is_empty() {
                        return None;
                    }
                    // By definition, we have a partial packet or partial codepoint
                    return Some(Ok(ScannedItem::Unknown(
                        self.buffer.drain(..).collect(),
                        Error::InvalidUTF8Sequence.into(),
                    )));
                }
                Ok(_) => (), // Might not be enough read yet
                Err(e) => return Some(Err(e.into())),
            }
            required_bytes = match ScannedItem::required_bytes(buf) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
        }

        // Now we have enough data to do something with it.

        // TODO: scan rapidly and collect all UTF8 text in one go rather than depending on the optimiser to make it
        // efficient.
        match ScannedItem::deserialize(buf) {
            Ok((event, used)) => {
                self.buffer.drain(..used);
                Some(Ok(event))
            }
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
}
