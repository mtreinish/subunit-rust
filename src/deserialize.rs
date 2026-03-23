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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::Serializable;

    #[test]
    fn test_u8_deserialize_empty() {
        let result = u8::deserialize(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_u8_deserialize_ok() {
        let (val, size) = u8::deserialize(&[0x42]).unwrap();
        assert_eq!(val, 0x42);
        assert_eq!(size, 1);
    }

    #[test]
    fn test_u16_deserialize_empty() {
        let result = u16::deserialize(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_u16_deserialize_one_byte() {
        let result = u16::deserialize(&[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_u16_deserialize_ok() {
        let (val, size) = u16::deserialize(&[0x01, 0x02]).unwrap();
        assert_eq!(val, 0x0102);
        assert_eq!(size, 2);
    }

    #[test]
    fn test_string_required_bytes_empty() {
        // Empty input: needs at least 1 byte for the length prefix
        let required = String::required_bytes(&[]).unwrap();
        assert_eq!(required, 1);
    }

    #[test]
    fn test_string_required_bytes_with_length() {
        // Length prefix says 3 bytes of content, using 1-byte encoding
        // So total = 1 (length prefix) + 3 (content) = 4
        let required = String::required_bytes(&[3, b'a', b'b', b'c']).unwrap();
        assert_eq!(required, 4);
    }

    #[test]
    fn test_string_required_bytes_just_length_prefix() {
        // Exactly 1 byte: the length prefix itself (value=5)
        // bytes.len() == required (1 == 1), so the < check passes and we proceed
        // to parse the number and return 1 + 5 = 6
        // If mutated to <=, it would return 1 early instead of 6
        let required = String::required_bytes(&[5]).unwrap();
        assert_eq!(required, 6);
    }

    #[test]
    fn test_string_required_bytes_two_byte_length() {
        // 2-byte length prefix for value 100: 0x40 | (100 >> 8), 100 & 0xFF = [0x40, 0x64]
        let num = SubunitNumber::new(100).unwrap();
        let mut buf = Vec::new();
        num.serialize(&mut buf).unwrap();
        buf.extend(vec![b'x'; 100]);
        let required = String::required_bytes(&buf).unwrap();
        assert_eq!(required, 102); // 2 (length prefix) + 100 (content)
    }

    #[test]
    fn test_string_deserialize_roundtrip() {
        let original = "hello world".to_string();
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let (deserialized, size) = String::deserialize(&buf).unwrap();
        assert_eq!(deserialized, original);
        assert_eq!(size, buf.len());
    }

    #[test]
    fn test_string_deserialize_invalid_utf8() {
        // Length prefix says 2 bytes, followed by invalid UTF-8
        let buf = [2, 0xFF, 0xFE];
        let result = String::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_vec_u8_deserialize_empty_input() {
        let result = Vec::<u8>::deserialize(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_vec_u8_deserialize_truncated() {
        // Length prefix says 5 bytes but only 2 are provided
        let buf = [5, b'a', b'b'];
        let result = Vec::<u8>::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_vec_u8_deserialize_ok() {
        let buf = [3, b'a', b'b', b'c'];
        let (val, size) = Vec::<u8>::deserialize(&buf).unwrap();
        assert_eq!(val, vec![b'a', b'b', b'c']);
        assert_eq!(size, 4);
    }

    #[test]
    fn test_vec_u8_deserialize_exact_length() {
        // Length prefix says 1 byte, exactly 1 byte of content follows
        // total = 1 (length prefix) + 1 (content) = 2
        // This catches + -> - (would check bytes.len() < 1 - 1 = 0, passes incorrectly for empty)
        // and + -> * (would check bytes.len() < 1 * 1 = 1, which is wrong)
        let buf = [1, b'x'];
        let (val, size) = Vec::<u8>::deserialize(&buf).unwrap();
        assert_eq!(val, vec![b'x']);
        assert_eq!(size, 2);
    }

    #[test]
    fn test_vec_u8_deserialize_missing_one_byte() {
        // Length says 3, but only 2 bytes of content (total 3 bytes, need 4)
        let buf = [3, b'a', b'b'];
        let result = Vec::<u8>::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_vec_u8_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 5];
        let as_tuple = ("name".to_string(), original.clone());
        let mut buf = Vec::new();
        as_tuple.serialize(&mut buf).unwrap();
        // Deserialize the string first, then the vec
        let (name, name_size) = String::deserialize(&buf).unwrap();
        assert_eq!(name, "name");
        let (val, _) = Vec::<u8>::deserialize(&buf[name_size..]).unwrap();
        assert_eq!(val, original);
    }
}
