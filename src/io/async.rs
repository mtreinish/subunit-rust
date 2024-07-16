//! Asynchronous I/O module

use std::collections::VecDeque;

use async_stream::try_stream;
use tokio::io::AsyncReadExt;
use tokio_stream::Stream;

use crate::{deserialize::Deserializable, types::stream::ScannedItem, Error, GenError, GenResult};

async fn next<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut VecDeque<u8>,
) -> GenResult<Option<ScannedItem>> {
    let buf = buffer.make_contiguous();
    let mut required_bytes = match ScannedItem::required_bytes(buf) {
        Ok(v) => v,
        Err(e) => Err(GenError::from(e))?,
    };
    while buf.len() < required_bytes {
        match reader.read(buf).await {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }

                // By definition, we have a partial packet or partial codepoint
                return Ok(Some(ScannedItem::Unknown(
                    buffer.drain(..).collect(),
                    Error::InvalidUTF8Sequence.into(),
                )));
            }
            Ok(_) => (), // Might not be enough read yet
            Err(e) => Err(GenError::from(e))?,
        }
        required_bytes = match ScannedItem::required_bytes(buf) {
            Ok(v) => v,
            Err(e) => Err(GenError::from(e))?,
        };
    }

    // Now we have enough data to do something with it.

    // TODO: scan rapidly and collect all UTF8 text in one go rather than depending on the optimiser to make it
    // efficient.
    match ScannedItem::deserialize(buf) {
        Ok((event, used)) => {
            buffer.drain(..used);
            Ok(Some(event))
        }
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
