//! Deserialization of events

use crate::{types::number::SubunitNumber, Error, GenResult};

/// Deserialization of Subunit types from a byte slice.
pub trait Deserializable {
    /// The minimum number of bytes that might be required to deserialize this
    /// type from the front of the slice. If the type cannot be deserialized at
    /// all, return an error.
    ///
    /// The count is a minimum because additional bytes may be required once the
    /// actual value is available. For instance, the minimum bytes for a UTF8
    /// codepoint is 1, buf if the codepoint is a multi-byte codepoint,
    /// additional bytes are required, and because of the way UTF8 is encoded,
    /// each byte can only reveal the requirement for one more byte.
    ///
    /// However for error handling, knowing how many bytes to skip over is very
    /// useful, so when required_bytes returns a value <= len(bytes), the caller
    /// can use that to skip over bytes to the next thing, if deserialising
    /// fails.
    fn required_bytes(bytes: &[u8]) -> GenResult<usize>;
    /// Deserialize the type from the slice.
    fn deserialize(bytes: &[u8]) -> GenResult<(Self, usize)>
    where
        Self: Sized;
}

impl Deserializable for u8 {
    fn required_bytes(_bytes: &[u8]) -> GenResult<usize> {
        Ok(1)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(u8, usize)> {
        if bytes.len() < u8::required_bytes(bytes)? {
            return Err(Error::NotEnoughBytes.into());
        }
        Ok((bytes[0], 1))
    }
}

impl Deserializable for u16 {
    fn required_bytes(_bytes: &[u8]) -> GenResult<usize> {
        Ok(2)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(u16, usize)> {
        if bytes.len() < u16::required_bytes(bytes)? {
            return Err(Error::NotEnoughBytes.into());
        }
        Ok((u16::from_be_bytes(bytes[..2].try_into().unwrap()), 2))
    }
}

impl Deserializable for String {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        let required = SubunitNumber::required_bytes(bytes)?;
        if bytes.len() < required {
            return Ok(required);
        }
        let (length, required) = SubunitNumber::deserialize(&bytes[..required])?;
        // The length is the number of bytes in the string, plus the length of the number prefixing it
        Ok(length.as_u32() as usize + required)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(String, usize)> {
        let (vec, length) = Vec::<u8>::deserialize(bytes)?;

        String::from_utf8(vec)
            .map(|s| (s, length))
            .map_err(|_| Error::InvalidUTF8Sequence.into())
    }
}

impl Deserializable for Vec<u8> {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        String::required_bytes(bytes)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Vec<u8>, usize)> {
        let required = String::required_bytes(bytes)?;
        if bytes.len() < required {
            return Err(Error::NotEnoughBytes.into());
        }
        let (length, required) = SubunitNumber::deserialize(&bytes[..required])?;
        // The length is the number of bytes in the string, plus the length of the number prefixing it
        if bytes.len() < length.as_u32() as usize + required {
            return Err(Error::NotEnoughBytes.into());
        }
        Ok((
            bytes[required..length.as_u32() as usize + required].to_vec(),
            length.as_u32() as usize + required,
        ))
    }
}

impl Deserializable for Vec<String> {
    fn required_bytes(_bytes: &[u8]) -> GenResult<usize> {
        unreachable!("Vec<String>::required_bytes is not required for this implementation");
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Vec<String>, usize)> {
        let (length, mut offset) = SubunitNumber::deserialize(bytes)?;
        let mut result = vec![];
        for _ in 0..length.as_u32() {
            let (string, size) = String::deserialize(&bytes[offset..])?;
            result.push(string);
            offset += size;
        }
        Ok((result, offset))
    }
}
