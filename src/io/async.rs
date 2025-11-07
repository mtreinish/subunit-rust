//! Asynchronous I/O module

use std::collections::VecDeque;

use async_stream::try_stream;
use tokio::io::AsyncReadExt;
use tokio_stream::Stream;

use crate::{deserialize::Deserializable, types::stream::ScannedItem, Error, GenError, GenResult};

/// Ask a struct to write itself to some impl AsyncWrite
#[async_trait::async_trait]
pub trait WriteIntoAsync {
    /// Write the struct to the writer
    async fn write_into(
        &self,
        writer: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()>;
}

async fn next<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut VecDeque<u8>,
) -> GenResult<Option<ScannedItem>> {
    // VecDequeue doesn't reserve space, and like Read AsyncRead only uses
    // allocated space (ReadBuf's intent aside). So we use VecDequeue to
    // minimise overheads, but do not actually read into it.
    let mut required_bytes = {
        let buf = buffer.make_contiguous();
        match ScannedItem::required_bytes(buf) {
            Ok(v) => v,
            Err(e) => Err(GenError::from(e))?,
        }
    };
    while buffer.len() < required_bytes {
        let mut read_buffer = [0u8; 8192];
        match reader.read(&mut read_buffer).await {
            Ok(0) => {
                if buffer.is_empty() {
                    return Ok(None);
                }

                // By definition, we have a partial packet or partial byte
                return Ok(Some(ScannedItem::Unknown(
                    buffer.drain(..).collect(),
                    Error::NotEnoughBytes.into(),
                )));
            }
            Ok(bytes_read) => {
                // Might not be enough read yet
                buffer.extend(read_buffer[..bytes_read].iter());
            }
            Err(e) => Err(GenError::from(e))?,
        }
        {
            let buf = buffer.make_contiguous();
            required_bytes = match ScannedItem::required_bytes(buf) {
                Ok(v) => v,
                Err(e) => Err(GenError::from(e))?,
            };
        }
    }

    // Now we have enough data to do something with it.

    let buf = buffer.make_contiguous();
    match ScannedItem::deserialize(buf) {
        Ok((ScannedItem::Event(event), used)) => {
            buffer.drain(..used);
            Ok(Some(ScannedItem::Event(event)))
        }
        Ok((ScannedItem::Bytes(_), _)) => {
            // Collect all consecutive non-event bytes into a single item
            let mut bytes = Vec::new();
            while let Some(&byte) = buffer.front() {
                if byte == crate::constants::V2_SIGNATURE {
                    break;
                }
                bytes.push(buffer.pop_front().unwrap());
            }
            Ok(Some(ScannedItem::Bytes(bytes)))
        }
        Ok((ScannedItem::Unknown(data, e), _)) => Ok(Some(ScannedItem::Unknown(data, e))),
        Err(e) => {
            // We know from the loop above that we had enough bytes, and this is not IO: some form of junk.
            // We have an invalid char or failed crc32 or similar.
            Ok(Some(ScannedItem::Unknown(
                buffer.drain(..required_bytes).collect(),
                e,
            )))
        }
    }
}

/// Iterate over a Readable, yielding the contents as `ScannedItems`.
pub fn iter_stream<R: AsyncReadExt + Unpin>(
    mut reader: R,
) -> impl Stream<Item = GenResult<ScannedItem>> {
    try_stream! {
        // Maximum buffer needed to process subunit packets is 4MB
        let mut buffer = VecDeque::<u8>::with_capacity(4 * 1024 * 1024);

        // NB: its likely that an async-native version of the logic would produce a nicer state machine; OTOH this way way have just one implementation of the core.

        while let Some(item) = next(&mut reader, &mut buffer).await? {
            yield item;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio_stream::StreamExt;

    use crate::{
        io::r#async::iter_stream,
        serialize::Serializable,
        types::{event::Event, stream::ScannedItem, teststatus::TestStatus},
    };

    #[tokio::test]
    async fn test_iter_stream() {
        // Construct a buffer containing a simple v2 stream

        let events = vec![
            Event::new(TestStatus::Success).test_id("foo").build(),
            Event::new(TestStatus::Success).test_id("bar").build(),
            Event::new(TestStatus::Success).test_id("baz").build(),
        ];

        let mut buf = Vec::new();
        for event in events {
            event.serialize(&mut buf).unwrap();
        }

        let stream = iter_stream(&buf[..]);
        let results = stream
            .collect::<Result<Vec<ScannedItem>, _>>()
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_stream_with_invalid_utf8() {
        // Test that we can parse a stream with invalid UTF-8 bytes interleaved
        let event = Event::new(TestStatus::Success).test_id("test").build();

        let mut buffer = Vec::new();
        // Add some invalid UTF-8 bytes (0xFF is not valid UTF-8 start byte)
        buffer.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        // Add a valid event
        event.serialize(&mut buffer).unwrap();
        // Add more invalid UTF-8
        buffer.extend_from_slice(&[0x80, 0x81]);

        let stream = iter_stream(&buffer[..]);
        let items: Vec<_> = stream.collect::<Result<Vec<_>, _>>().await.unwrap();

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
