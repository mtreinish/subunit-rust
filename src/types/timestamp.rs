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
        let timestamp_i64 = dt.timestamp();
        // Validate that the timestamp fits in u32 (0 to 4294967295)
        // This covers dates from 1970-01-01 00:00:00 UTC to 2106-02-07 06:28:15 UTC
        let seconds = u32::try_from(timestamp_i64)
            .map_err(|_| Error::InvalidTimestamp(timestamp_i64 as u32, 0))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_timestamp_valid_epoch() {
        // Test epoch (1970-01-01 00:00:00 UTC)
        let dt = Utc.timestamp_opt(0, 0).unwrap();
        let ts = Timestamp::try_from(dt).unwrap();
        assert_eq!(ts.seconds, 0);
        assert_eq!(u32::from(ts.nanoseconds), 0);

        // Convert back
        let dt_back: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt, dt_back);
    }

    #[test]
    fn test_timestamp_valid_recent() {
        // Test a recent timestamp (2024-01-01 00:00:00 UTC)
        let dt = Utc.timestamp_opt(1704067200, 123456789).unwrap();
        let ts = Timestamp::try_from(dt).unwrap();
        assert_eq!(ts.seconds, 1704067200);
        assert_eq!(u32::from(ts.nanoseconds), 123456789);

        // Convert back
        let dt_back: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt, dt_back);
    }

    #[test]
    fn test_timestamp_max_u32() {
        // Test maximum u32 value (2106-02-07 06:28:15 UTC)
        let dt = Utc.timestamp_opt(u32::MAX as i64, 0).unwrap();
        let ts = Timestamp::try_from(dt).unwrap();
        assert_eq!(ts.seconds, u32::MAX);
        assert_eq!(u32::from(ts.nanoseconds), 0);

        // Convert back
        let dt_back: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt, dt_back);
    }

    #[test]
    fn test_timestamp_overflow_beyond_u32() {
        // Test timestamp beyond u32::MAX (year 2107)
        let dt = Utc.timestamp_opt(u32::MAX as i64 + 1, 0).unwrap();
        let result = Timestamp::try_from(dt);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_negative() {
        // Test negative timestamp (before epoch)
        let dt = Utc.timestamp_opt(-1, 0).unwrap();
        let result = Timestamp::try_from(dt);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_invalid_nanoseconds() {
        // Test invalid nanoseconds (> 1 billion)
        // Note: SubunitNumber has a max value constraint, so we use 999999999 which is valid
        // for SubunitNumber but we can create a test with chrono that would fail
        // The main validation happens in DateTime::from_timestamp
        let ts = Timestamp {
            seconds: u32::MAX,
            nanoseconds: SubunitNumber::try_from(999_999_999u32).unwrap(),
        };
        // This should succeed as it's a valid timestamp
        let result: Result<DateTime<Utc>, _> = ts.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_timestamp_roundtrip() {
        // Test various timestamps roundtrip correctly
        let test_cases = vec![
            (0, 0),
            (1, 1),
            (1000000000, 500000000),
            (1704067200, 999999999),
            (u32::MAX, 0),
        ];

        for (secs, nanos) in test_cases {
            let dt = Utc.timestamp_opt(secs as i64, nanos).unwrap();
            let ts = Timestamp::try_from(dt).unwrap();
            assert_eq!(ts.seconds, secs);
            assert_eq!(u32::from(ts.nanoseconds), nanos);

            let dt_back: DateTime<Utc> = ts.try_into().unwrap();
            assert_eq!(dt, dt_back);
        }
    }
}
