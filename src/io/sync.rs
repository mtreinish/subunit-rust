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
                    // EOF reached - check one more time if we have enough bytes
                    // before declaring this Unknown. This handles the case where
                    // required_bytes returns a conservative estimate that gets
                    // refined as more data becomes available.
                    if self.buffer.is_empty() {
                        return None;
                    }

                    let buf = self.buffer.make_contiguous();
                    let required_bytes = match ScannedItem::required_bytes(buf) {
                        Ok(v) => v,
                        Err(e) => return Some(Err(e)),
                    };

                    if buf.len() >= required_bytes {
                        // We actually do have enough data
                        break;
                    }

                    // Truly incomplete packet at EOF
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

    #[test]
    fn test_many_events() {
        // Test that we can parse a large number of events without losing any
        const NUM_EVENTS: usize = 3461;

        let mut buffer = Vec::new();
        for i in 0..NUM_EVENTS {
            let event = Event::new(TestStatus::Success)
                .test_id(&format!("test_{}", i))
                .build();
            event.serialize(&mut buffer).unwrap();
        }

        let mut count = 0;
        for item in sync::iter_stream(Cursor::new(&buffer)) {
            match item {
                Ok(ScannedItem::Event(_)) => count += 1,
                Ok(ScannedItem::Unknown(data, e)) => {
                    panic!(
                        "Unexpected Unknown item at event {}: {} bytes, error: {:?}",
                        count,
                        data.len(),
                        e
                    );
                }
                Ok(ScannedItem::Bytes(_)) => {}
                Err(e) => panic!("Error reading event: {:?}", e),
            }
        }

        assert_eq!(count, NUM_EVENTS);
    }
}
