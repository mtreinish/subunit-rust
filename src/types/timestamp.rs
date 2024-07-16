//! Subunit timestamps

use std::io::Write;

use chrono::{DateTime, Utc};

use crate::{
    deserialize::Deserializable, serialize::Serializable, types::number::SubunitNumber, Error,
    GenError, GenResult,
};

/// Subunit timestamps are UTC time since epoch with a u32 seconds component and
/// a SubunitNumber nanoseconds component.
///
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L315)
#[derive(Debug, Clone, PartialEq)]
pub struct Timestamp {
    /// The seconds component of the timestamp
    pub seconds: u32,
    /// The nanoseconds component of the timestamp
    pub nanoseconds: SubunitNumber,
}

impl Serializable for Timestamp {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        //  TIMESTAMP = SECONDS NANOS
        self.seconds.wire_size()? + self.nanoseconds.wire_size()?
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        self.seconds.serialize(out)?;
        self.nanoseconds.serialize(out)
    }
}

impl Deserializable for Timestamp {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        //  TIMESTAMP = SECONDS NANOS
        let required = 5;
        if bytes.len() < required {
            return Ok(required);
        }
        let required = SubunitNumber::required_bytes(&bytes[4..5])?;
        // The length is the 4 for the u32 in seconds + the variable length nanos
        Ok(4 + required)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Timestamp, usize)> {
        let required = Timestamp::required_bytes(bytes)?;
        if bytes.len() < required {
            return Err(Error::NotEnoughBytes.into());
        }
        // infallible via guard above
        let seconds = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let nanoseconds = SubunitNumber::deserialize(&bytes[4..required])?.0;
        Ok((
            Timestamp {
                seconds,
                nanoseconds,
            },
            required,
        ))
    }
}

impl TryFrom<DateTime<Utc>> for Timestamp {
    type Error = GenError;
    fn try_from(dt: DateTime<Utc>) -> GenResult<Self> {
        let seconds = dt.timestamp() as u32;
        let nanoseconds = dt.timestamp_subsec_nanos().try_into()?;
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }
}

impl TryFrom<Timestamp> for DateTime<Utc> {
    type Error = GenError;
    fn try_from(ts: Timestamp) -> GenResult<Self> {
        DateTime::from_timestamp(ts.seconds as i64, ts.nanoseconds.into())
            .ok_or_else(|| Error::InvalidTimestamp(ts.seconds, ts.nanoseconds.into()).into())
    }
}
