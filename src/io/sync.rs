//! Synchronous I/O module

use std::{collections::VecDeque, io::Read};

use crate::{deserialize::Deserializable, types::stream::ScannedItem, Error, GenResult};

/// Ask a struct to write itself to some impl Write
pub trait WriteInto {
    /// Write the struct to the writer
    fn write_into(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()>;
}

/// Look for subunit events in an input stream.
#[derive(Debug)]
pub struct Scanner<R> {
    buffer: VecDeque<u8>,
    reader: R,
    read_buf: Box<[u8; 4096]>,
}

/// Iterate over a Readable, yielding the contents as `ScannedItems`.
pub fn iter_stream<R: Read>(reader: R) -> impl Iterator<Item = GenResult<ScannedItem>> {
    // Maximum buffer needed to process subunit packets is 4MB
    let buffer = VecDeque::<u8>::with_capacity(4 * 1024 * 1024);
    Scanner {
        buffer,
        reader,
        read_buf: Box::new([0u8; 4096]),
    }
}

impl<R> Iterator for Scanner<R>
where
    R: Read,
{
    type Item = GenResult<ScannedItem>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let buf = self.buffer.make_contiguous();
            let required_bytes = match ScannedItem::required_bytes(buf) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            if buf.len() >= required_bytes {
                // We have enough data - parse it
                break;
            }

            // Need to read more data from the reader
            // Use the reusable read buffer to avoid allocations
            match self.reader.read(&mut self.read_buf[..]) {
                Ok(0) => {
                    // EOF reached
                    if self.buffer.is_empty() {
                        return None;
                    }
                    // By definition, we have a partial packet or partial codepoint
                    return Some(Ok(ScannedItem::Unknown(
                        self.buffer.drain(..).collect(),
                        Error::InvalidUTF8Sequence.into(),
                    )));
                }
                Ok(n) => {
                    // Extend buffer with the bytes we actually read
                    self.buffer.extend(&self.read_buf[..n]);
                }
                Err(e) => return Some(Err(e.into())),
            }
        }

        // Now we have enough data to do something with it.
        let buf = self.buffer.make_contiguous();

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
                let buf = self.buffer.make_contiguous();
                let required_bytes = ScannedItem::required_bytes(buf).unwrap_or(1);
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

    use chrono::NaiveDate;

    use crate::{
        io::sync,
        serialize::Serializable,
        types::{event::Event, stream::ScannedItem, teststatus::TestStatus},
    };

    #[test]
    fn test_write_full_test_event_with_file_content() {
        let event = Event::new(TestStatus::InProgress)
            .test_id("A_test_id")
            .datetime(
                NaiveDate::from_ymd_opt(2014, 7, 8)
                    .unwrap()
                    .and_hms_opt(9, 10, 11)
                    .unwrap()
                    .and_utc(),
            )
            .unwrap()
            .tag("tag_a")
            .tag("tag_b")
            .mime_type("text/plain;charset=utf8")
            .file_content("stdout:''", b"stdout content")
            .build();
        let event_a = Event::new(TestStatus::Failed)
            .test_id("A_test_id")
            .datetime(
                NaiveDate::from_ymd_opt(2014, 7, 8)
                    .unwrap()
                    .and_hms_opt(9, 12, 1)
                    .unwrap()
                    .and_utc(),
            )
            .unwrap()
            .tag("tag_a")
            .tag("tag_b")
            .build();

        let mut buffer = event.to_vec().unwrap();
        event_a.serialize(&mut buffer).unwrap();

        let mut count = 0;
        for (parsed_event, event) in
            sync::iter_stream(Cursor::new(&buffer)).zip([event, event_a].iter())
        {
            count += 1;
            let parsed_event = parsed_event.unwrap();
            let ScannedItem::Event(parsed_event) = parsed_event else {
                panic!("Expected event, got {:?}", parsed_event);
            };
            assert_eq!(*event, parsed_event);
        }
        assert_eq!(count, 2, "Expected to read 2 events, got {}", count);
    }

    #[test]
    fn test_scanner_reads_owned_cursor() {
        // This test exposes the bug: Scanner fails when given ownership of the Cursor
        // (as opposed to borrowing it like the test above)
        let event = Event::new(TestStatus::Success).test_id("test").build();
        let buffer = event.to_vec().unwrap();

        // Pass owned Cursor - this should work but doesn't due to Scanner bug
        let mut count = 0;
        for item in sync::iter_stream(Cursor::new(buffer)) {
            let item = item.unwrap();
            if matches!(item, ScannedItem::Event(_)) {
                count += 1;
            }
        }

        assert_eq!(count, 1, "Expected 1 event, got {}", count);
    }
}
