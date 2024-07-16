//! Helpers for number types.

use std::{fmt::Debug, io::Write, ops::Add};

use crate::{
    constants::{self, NUMBER_KIND_MASK, NUMBER_VALUE_MASK},
    deserialize::Deserializable,
    serialize::Serializable,
    Error, GenError, GenResult,
};

/// The concept of the type of the encoding of a number, stored in the 2 most
/// significant bits of the number.
///
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L199)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub(crate) enum NumberType {
    OneByte = 0b00000000,
    TwoBytes = 0b01000000,
    ThreeBytes = 0b10000000,
    FourBytes = 0b11000000,
}

impl NumberType {
    pub fn new(byte: u8) -> NumberType {
        let number_type = byte & NUMBER_KIND_MASK;
        match number_type >> 6 {
            // 0b00, 1 octet
            0 => NumberType::OneByte,
            // 0b01, 2octets
            1 => NumberType::TwoBytes,
            // 0b10, 3 octets
            2 => NumberType::ThreeBytes,
            // 0b11, 4 octets
            _ => NumberType::FourBytes,
        }
    }
}

/// A subunit wire protocol number
///
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L199)
#[derive(Clone, Copy, PartialEq)]
pub enum SubunitNumber {
    /// A number that fits in one byte
    OneByte([u8; 1]),
    /// A number that fits in two bytes, in network order, with encoding mark.
    TwoBytes([u8; 2]),
    /// A number that fits in three bytes, in network order, with encoding mark.
    ThreeBytes([u8; 3]),
    /// A number that fits in four bytes, in network order, with encoding mark.
    FourBytes([u8; 4]),
}

impl Debug for SubunitNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SubunitNumber({} {:?})", self.as_u32(), self.as_bytes())
    }
}

impl SubunitNumber {
    pub fn new(value: u32) -> GenResult<Self> {
        if value > constants::MAX_NUMBER_VALUE {
            return Err(Error::TooLarge.into());
        }
        Ok(match value {
            /* 2^(8-2) */ 0..=63 => SubunitNumber::OneByte([value as u8]),
            /* 2^(16-2) */
            64..=16383 => {
                let mut bytes = (value as u16).to_be_bytes();
                bytes[0] |= NumberType::TwoBytes as u8;
                SubunitNumber::TwoBytes(bytes)
            }
            /* 2^(24-2) */
            16384..=4194303 => {
                let mut bytes = value.to_be_bytes();
                bytes[1] |= NumberType::ThreeBytes as u8;
                SubunitNumber::ThreeBytes(bytes[1..].try_into().unwrap())
            }
            /* 2^(32-2) */
            _ => {
                let mut bytes = value.to_be_bytes();
                bytes[0] |= NumberType::FourBytes as u8;
                SubunitNumber::FourBytes(bytes)
            }
        })
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            SubunitNumber::OneByte(value) => u32::from(value[0]),
            SubunitNumber::TwoBytes(value) => {
                u32::from(value[0] & NUMBER_VALUE_MASK) << 8 | u32::from(value[1])
            }
            SubunitNumber::ThreeBytes(value) => {
                u32::from(value[0] & NUMBER_VALUE_MASK) << 16
                    | u32::from(value[1]) << 8
                    | u32::from(value[2])
            }
            SubunitNumber::FourBytes(value) => {
                u32::from(value[0] & NUMBER_VALUE_MASK) << 24
                    | u32::from(value[1]) << 16
                    | u32::from(value[2]) << 8
                    | u32::from(value[3])
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SubunitNumber::OneByte(value) => value,
            SubunitNumber::TwoBytes(value) => value,
            SubunitNumber::ThreeBytes(value) => value,
            SubunitNumber::FourBytes(value) => value,
        }
    }
}

impl TryFrom<u32> for SubunitNumber {
    type Error = GenError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        SubunitNumber::new(value)
    }
}

impl TryFrom<usize> for SubunitNumber {
    type Error = GenError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        SubunitNumber::new(value.try_into()?)
    }
}

impl From<SubunitNumber> for u32 {
    fn from(value: SubunitNumber) -> Self {
        value.as_u32()
    }
}

impl Add<SubunitNumber> for u32 {
    type Output = GenResult<SubunitNumber>;
    fn add(self, other: SubunitNumber) -> Self::Output {
        let result = self.checked_add(other.as_u32());
        match result {
            Some(value) => Ok(value.try_into()?),
            None => Err(Error::TooLarge.into()),
        }
    }
}

impl Add<SubunitNumber> for usize {
    type Output = GenResult<SubunitNumber>;
    fn add(self, other: SubunitNumber) -> Self::Output {
        let result = self.checked_add(other.as_u32() as usize);
        match result {
            Some(value) => Ok(value.try_into()?),
            None => Err(Error::TooLarge.into()),
        }
    }
}
impl Add<SubunitNumber> for GenResult<SubunitNumber> {
    type Output = GenResult<SubunitNumber>;
    fn add(self, other: SubunitNumber) -> Self::Output {
        let result = self?.as_u32().checked_add(other.as_u32());
        match result {
            Some(value) => Ok(value.try_into()?),
            None => Err(Error::TooLarge.into()),
        }
    }
}

impl Add for SubunitNumber {
    type Output = GenResult<SubunitNumber>;
    fn add(self, other: SubunitNumber) -> Self::Output {
        let result = self.as_u32().checked_add(other.as_u32());
        match result {
            Some(value) => Ok(value.try_into()?),
            None => Err(Error::TooLarge.into()),
        }
    }
}

impl Serializable for SubunitNumber {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        match self.as_u32() {
            0..=63 => SubunitNumber::new(1),
            64..=16383 => SubunitNumber::new(2),
            16384..=4194303 => SubunitNumber::new(3),
            _ => SubunitNumber::new(4),
        }
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        out.write_all(self.as_bytes())?;
        Ok(())
    }
}

impl Deserializable for SubunitNumber {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        if bytes.is_empty() {
            return Ok(1);
        }
        Ok(match NumberType::new(bytes[0]) {
            NumberType::OneByte => 1,
            NumberType::TwoBytes => 2,
            NumberType::ThreeBytes => 3,
            NumberType::FourBytes => 4,
        })
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(SubunitNumber, usize)> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes.into());
        }
        let size = SubunitNumber::required_bytes(bytes)?;
        if bytes.len() < size {
            return Err(Error::NotEnoughBytes.into());
        }
        let b = &bytes[..size];
        // The unwraps are infallible - the size is matched
        Ok((
            match NumberType::new(bytes[0]) {
                NumberType::OneByte => SubunitNumber::OneByte(b.try_into().unwrap()),
                NumberType::TwoBytes => SubunitNumber::TwoBytes(b.try_into().unwrap()),
                NumberType::ThreeBytes => SubunitNumber::ThreeBytes(b.try_into().unwrap()),
                NumberType::FourBytes => SubunitNumber::FourBytes(b.try_into().unwrap()),
            },
            size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::NumberType;
    use super::SubunitNumber;

    #[test]
    fn test_number_type() {
        assert_eq!(NumberType::new(0b00000000), NumberType::OneByte);
        assert_eq!(NumberType::new(0b00111111), NumberType::OneByte);
        assert_eq!(NumberType::new(0b01000000), NumberType::TwoBytes);
        assert_eq!(NumberType::new(0b01111111), NumberType::TwoBytes);
        assert_eq!(NumberType::new(0b10000000), NumberType::ThreeBytes);
        assert_eq!(NumberType::new(0b10111111), NumberType::ThreeBytes);
        assert_eq!(NumberType::new(0b11000000), NumberType::FourBytes);
        assert_eq!(NumberType::new(0b11111111), NumberType::FourBytes);
    }

    #[test]
    fn test_subunit_number() {
        let number = SubunitNumber::new(0).unwrap();
        assert_eq!(number.as_u32(), 0);
        assert_eq!(number.as_bytes(), &[0]);
        let number = SubunitNumber::new(63).unwrap();
        assert_eq!(number.as_u32(), 63);
        assert_eq!(number.as_bytes(), &[0b00111111]);
        let number = SubunitNumber::new(64).unwrap();
        assert_eq!(number.as_u32(), 64);
        assert_eq!(number.as_bytes(), &[0b01000000, 64]);
        let number = SubunitNumber::new(16383).unwrap();
        assert_eq!(number.as_u32(), 16383);
        assert_eq!(number.as_bytes(), &[0b01111111, 255]);
        let number = SubunitNumber::new(16384).unwrap();
        assert_eq!(number.as_u32(), 16384);
        assert_eq!(number.as_bytes(), &[0b10000000, 64, 0]);
        let number = SubunitNumber::new(4194303).unwrap();
        assert_eq!(number.as_u32(), 4194303);
        assert_eq!(number.as_bytes(), &[0b10111111, 255, 255]);
        let number = SubunitNumber::new(4194304).unwrap();
        assert_eq!(number.as_u32(), 4194304);
        assert_eq!(number.as_bytes(), &[0b11000000, 64, 0, 0]);
        let number = SubunitNumber::new(0x3FFFFFFF).unwrap();
        assert_eq!(number.as_u32(), 0x3FFFFFFF);
        assert_eq!(number.as_bytes(), &[0b11111111, 255, 255, 255]);
    }
}
