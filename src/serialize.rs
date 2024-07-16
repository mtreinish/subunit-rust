//! Serialization of events

use std::io::Write;

use crc32fast::Hasher;

use crate::{types::number::SubunitNumber, GenResult};

/// Trait that describes the serialization requirements for Subunit events.
///
/// Of particular note is the 'look ahead' `wire_size` method, which allows avoiding bulk data copying.
pub trait Serializable {
    /// Returns the size of a given implementor in bytes after serialization.
    ///
    /// This is used to calculate the size of the serialized event before data
    /// copying takes place, in order to write the length-prefix for variable-sized
    /// components.
    fn wire_size(&self) -> GenResult<SubunitNumber>;

    /// Write the instance to the given writer.
    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()>;
}

impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        match self {
            Some(inner) => inner.wire_size(),
            None => SubunitNumber::new(0),
        }
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        match self {
            Some(inner) => inner.serialize(out),
            None => Ok(()),
        }
    }
}

impl<T> Serializable for Vec<T>
where
    T: Serializable,
{
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        let mut size = SubunitNumber::new(self.len() as u32)?.wire_size()?;
        for item in self {
            size = (size + item.wire_size()?)?;
        }
        Ok(size)
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        SubunitNumber::try_from(self.len())?.serialize(out)?;
        for item in self {
            item.serialize(out)?;
        }
        Ok(())
    }
}

impl<T, U> Serializable for (T, U)
where
    T: Serializable,
    U: Serializable,
{
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        let (a, b) = self;
        a.wire_size()? + b.wire_size()?
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        let (a, b) = self;
        a.serialize(out)?;
        b.serialize(out)
    }
}

impl Serializable for u8 {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        SubunitNumber::new(1)
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        out.write_all(&[*self])?;
        Ok(())
    }
}

impl Serializable for u32 {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        SubunitNumber::new(4)
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        out.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl Serializable for String {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        self.len() + SubunitNumber::new(self.len() as u32)?.wire_size()?
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        SubunitNumber::try_from(self.len())?.serialize(out)?;
        out.write_all(self.as_bytes())?;
        Ok(())
    }
}

pub struct Writer<'a, W> {
    buffer: &'a mut W,
    hasher: Hasher,
}

impl<'a, W> Writer<'a, W>
where
    W: Write,
{
    pub(crate) fn new(buffer: &'a mut W) -> Self {
        Writer {
            buffer,
            hasher: Hasher::new(),
        }
    }

    pub(crate) fn finalize(self) -> u32 {
        self.hasher.finalize()
    }
}

impl<W> Write for Writer<'_, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}
