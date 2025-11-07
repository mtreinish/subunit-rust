//! Subunit event
use std::io::Write;

use chrono::{DateTime, Utc};
use crc32fast::Hasher;
use enumset::EnumSet;

use crate::{
    constants::{self, V2_SIGNATURE},
    deserialize::Deserializable,
    serialize::{Serializable, Writer},
    Error, GenResult,
};

use super::{
    eventfeatures::EventFeatures, file::File, number::SubunitNumber, teststatus::TestStatus,
    timestamp::Timestamp,
};

macro_rules! safe_read {
    ($expr:expr) => {
        match $expr {
            ::std::result::Result::Ok(val) => val,
            ::std::result::Result::Err(size) => {
                return ::std::result::Result::Ok(size);
            }
        }
    };
}

macro_rules! safe_de {
    ($expr:expr) => {
        match $expr {
            ::std::result::Result::Ok(val) => val,
            ::std::result::Result::Err(_size) => {
                return ::std::result::Result::Err($crate::Error::NotEnoughBytes.into());
            }
        }
    };
}

/// Construct an event incrementally
pub struct EventBuilder(Event);

impl EventBuilder {
    /// Set the test id
    pub fn test_id(mut self, test_id: &str) -> Self {
        self.0.test_id = Some(test_id.to_string());
        self
    }

    /// Set the event timestamp
    pub fn datetime(mut self, datetime: DateTime<Utc>) -> GenResult<Self> {
        self.0.timestamp = Some(datetime.try_into()?);
        Ok(self)
    }

    /// Add a tag to the event
    pub fn tag(mut self, tag: &str) -> Self {
        if self.0.tags.is_none() {
            self.0.tags = Some(Vec::new());
        }
        self.0.tags.as_mut().unwrap().push(tag.to_string());
        self
    }

    /// Set the file mime type
    pub fn mime_type(mut self, mime_type: &str) -> Self {
        self.0.file.mime_type = Some(mime_type.to_string());
        self
    }

    /// Set the file content
    pub fn file_content(mut self, name: &str, content: &[u8]) -> Self {
        self.0.file.file = Some((name.to_string(), content.to_vec()));
        self
    }

    /// Set the event as end of file
    pub fn end_of_file(mut self) -> Self {
        self.0.file.eof = true;
        self
    }

    /// Set the event as runnable
    pub fn runnable(mut self) -> Self {
        self.0.runnable = true;
        self
    }

    /// Set the routing code
    pub fn route_code(mut self, route_code: &str) -> Self {
        self.0.route_code = Some(route_code.to_string());
        self
    }

    /// Build the event
    pub fn build(self) -> Event {
        self.0
    }
}

impl EventBuilder {}

/// A subunit event
///
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L147)
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// The status of the event
    pub status: TestStatus,
    /// The test id if present
    pub test_id: Option<String>,
    /// The timestamp if present
    pub timestamp: Option<Timestamp>,
    /// File content details
    pub file: File,
    /// The routing code if present. Routing codes are used to route IO back to test sources
    pub route_code: Option<String>,
    /// Event tags if present
    pub tags: Option<Vec<String>>,
    /// When true indicates that this test (route_code + test_id) is individually runnable
    pub runnable: bool,
}

impl Event {
    /// Construct an event.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(status: TestStatus) -> EventBuilder {
        EventBuilder(Self {
            status,
            test_id: None,
            timestamp: None,
            file: File::default(),
            route_code: None,
            tags: None,
            runnable: false,
        })
    }

    /// Write the event to a byte vector. The maximum size of a serialized event
    /// is 4MiB.
    ///
    /// To avoid allocations, a single vector with reserved capacity can be used
    /// and reused via the `Serializable` trait.
    ///
    /// The function can fail if the event is too large to serialize : Subunit
    /// defines a 4MB limit. On failure, partial content may have been written.
    pub fn to_vec(&self) -> GenResult<Vec<u8>> {
        let size = self.wire_size()?.as_u32() as usize;
        let mut buffer = Vec::with_capacity(size);
        self.serialize(&mut buffer)?;
        Ok(buffer)
    }

    fn make_flags(&self) -> u16 {
        let mut flags = EnumSet::new();

        if self.timestamp.is_some() {
            flags |= EventFeatures::Timestamp;
        }
        if self.test_id.is_some() {
            flags |= EventFeatures::TestId;
        }
        if self.tags.is_some() {
            flags |= EventFeatures::Tags;
        }
        if self.file.mime_type.is_some() {
            flags |= EventFeatures::FileMimeType;
        }
        if self.file.file.is_some() {
            flags |= EventFeatures::FileContent;
        }
        if self.file.eof {
            flags |= EventFeatures::EndOfFile;
        }
        if self.route_code.is_some() {
            flags |= EventFeatures::RoutingCode;
        }
        if self.runnable {
            flags |= EventFeatures::Runnable;
        }

        let version = 0x2000_u16; // version 0x2

        version | flags.as_repr() | self.status as u16
    }

    fn packet_length(base_length: u32) -> GenResult<SubunitNumber> {
        // The length of the packet length is self-referential, so we can't
        // simply serialise the length of all the other components. Instead, we allow extra space for the number of bytes required to encode the length of the packet itself.
        match base_length {
            0..=62 => 1_u32 + base_length,
            63..=16381 => 2_u32 + base_length,
            16382..=4194300 => 3_u32 + base_length, // == MAX_PACKET_LENGTH
            _ => return Err(Error::TooLarge.into()),
        }
        .try_into()
    }
}

impl Serializable for Event {
    fn wire_size(&self) -> GenResult<SubunitNumber> {
        //  PACKET = SIGNATURE FLAGS PACKET_LENGTH TIMESTAMP? TESTID? TAGS?
        //           MIME? FILECONTENT? ROUTING_CODE? CRC32
        let base_length = (V2_SIGNATURE.wire_size()?.as_u32()
            + 2 // flags u16
            // + SubunitNumber(...).wire_size() // packet length- see below
            + self.timestamp.wire_size()? // timestamp
            + self.test_id.wire_size()? // test_id
            + self.tags.wire_size()? // tags
            + self.file.wire_size()? // file content
            + self.route_code.wire_size()? // route code
            + SubunitNumber::new(4_u32)?)?; // crc32

        Self::packet_length(base_length.as_u32())
    }

    fn serialize<W: Write>(&self, out: &mut W) -> GenResult<()> {
        //  PACKET = SIGNATURE FLAGS PACKET_LENGTH TIMESTAMP? TESTID? TAGS?
        //           MIME? FILECONTENT? ROUTING_CODE? CRC32
        // Hash while writing
        let mut writer = Writer::new(out);
        crate::constants::V2_SIGNATURE.serialize(&mut writer)?;
        // TODO: make a flags struct to make this nicer?
        let flags = self.make_flags();
        writer.write_all(&flags.to_be_bytes())?;

        let packet_length = self.wire_size()?;
        packet_length.serialize(&mut writer)?;
        self.timestamp.serialize(&mut writer)?;
        self.test_id.serialize(&mut writer)?;
        self.tags.serialize(&mut writer)?;
        self.file.serialize(&mut writer)?;
        self.route_code.serialize(&mut writer)?;

        // Flush buffer into output and digest to calculate crc32
        let checksum = writer.finalize();
        out.write_all(&checksum.to_be_bytes())?;
        Ok(())
    }
}

impl Deserializable for Event {
    fn required_bytes(bytes: &[u8]) -> GenResult<usize> {
        //  PACKET = SIGNATURE FLAGS PACKET_LENGTH TIMESTAMP? TESTID? TAGS?
        //           MIME? FILECONTENT? ROUTING_CODE? CRC32
        let mut reader = Reader::new(bytes);
        let signature = safe_read!(reader.read::<u8>()?);
        if signature != V2_SIGNATURE {
            return Err(Error::InvalidSignature.into());
        }
        let flags = safe_read!(reader.read::<u16>()?);
        // TODO : wrapper type to avoid duplication?
        if flags & 0xF000 != constants::VERSION2 {
            return Err(Error::BadVersion(flags & 0xF00).into());
        }
        let _features = EnumSet::<EventFeatures>::from_repr_truncated(flags);
        let packet_length = safe_read!(reader.read::<SubunitNumber>()?);
        if packet_length.as_u32() > constants::MAX_PACKET_LENGTH {
            return Err(Error::TooLarge.into());
        }
        if (packet_length.as_u32() as usize) < reader.bytes_read {
            return Err(
                Error::LengthTooSmall(packet_length.as_u32(), reader.bytes_read as u32).into(),
            );
        }
        Ok(packet_length.as_u32() as usize)
    }

    fn deserialize(bytes: &[u8]) -> GenResult<(Self, usize)> {
        //  PACKET = SIGNATURE FLAGS PACKET_LENGTH TIMESTAMP? TESTID? TAGS?
        //           MIME? FILECONTENT? ROUTING_CODE? CRC32
        let mut reader = Reader::new(bytes);
        let signature = safe_de!(reader.read::<u8>()?);
        if signature != V2_SIGNATURE {
            return Err(Error::InvalidSignature.into());
        }
        let flags = safe_de!(reader.read::<u16>()?);
        // TODO : wrapper type to avoid duplication?
        if flags & 0xF000 != constants::VERSION2 {
            return Err(Error::BadVersion(flags & 0xF00).into());
        }
        let status = TestStatus::from(flags);
        let features = EnumSet::<EventFeatures>::from_repr_truncated(flags);
        let packet_length = safe_de!(reader.read::<SubunitNumber>()?).as_u32() as usize;
        if packet_length > constants::MAX_PACKET_LENGTH as usize {
            return Err(Error::TooLarge.into());
        }
        if packet_length < reader.bytes_read {
            return Err(
                Error::LengthTooSmall(packet_length as u32, reader.bytes_read as u32).into(),
            );
        }
        // Don't permit out of bound reads. From this point on, we don't
        // pre-check the length of reads.
        reader.set_slice_end(packet_length)?;
        let mut result = Event {
            status,
            test_id: None,
            timestamp: None,
            file: File::default(),
            route_code: None,
            tags: None,
            runnable: false,
        };

        // It is temping to iterate over the features, but the wire order iteration matters - TODO: see if that is possible

        if features.contains(EventFeatures::Reserved) {
            return Err(Error::Internal("Reserved feature".to_string()).into());
        }
        if features.contains(EventFeatures::Timestamp) {
            let timestamp = safe_de!(reader.read_without_estimating::<Timestamp>()?);
            result.timestamp = Some(timestamp);
        }
        if features.contains(EventFeatures::TestId) {
            let test_id = safe_de!(reader.read_without_estimating::<String>()?);
            result.test_id = Some(test_id);
        }
        if features.contains(EventFeatures::Tags) {
            let tags = safe_de!(reader.read_without_estimating::<Vec<String>>()?);
            result.tags = Some(tags);
        }
        if features.contains(EventFeatures::Runnable) {
            result.runnable = true;
        }
        if features.contains(EventFeatures::EndOfFile) {
            result.file.eof = true
        }
        // TODO: make safe_de reusable without hashing and push this down to the file struct
        if features.contains(EventFeatures::FileMimeType) {
            let mime = safe_de!(reader.read_without_estimating::<String>()?);
            result.file.mime_type = Some(mime);
        }
        if features.contains(EventFeatures::FileContent) {
            let name = safe_de!(reader.read_without_estimating::<String>()?);
            let content = safe_de!(reader.read_without_estimating::<Vec<u8>>()?);
            result.file.file = Some((name, content));
        }
        if features.contains(EventFeatures::RoutingCode) {
            let route_code = safe_de!(reader.read_without_estimating::<String>()?);
            result.route_code = Some(route_code);
        }

        let packet_crc32 = u32::from_be_bytes(
            reader.bytes[reader.bytes_read..reader.bytes_read + 4]
                .try_into()
                .unwrap(),
        );
        let measured_crc32 = reader.finalize();

        if measured_crc32 != packet_crc32 {
            return Err(Error::CRC32Mismatch(measured_crc32, packet_crc32).into());
        }

        Ok((result, packet_length))
    }
}

/// Helper to avoid some boilerplate in deserialization
struct Reader<'a> {
    bytes: &'a [u8],
    bytes_read: usize,
    hasher: Hasher,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bytes_read: 0,
            hasher: Hasher::new(),
        }
    }

    fn read<T>(&mut self) -> GenResult<Result<T, usize>>
    where
        T: Deserializable,
    {
        let required = T::required_bytes(&self.bytes[self.bytes_read..])?;
        if required > self.bytes.len() {
            return Ok(Err(required + self.bytes_read));
        }
        let val = T::deserialize(&self.bytes[self.bytes_read..])?;
        self.hasher
            .update(&self.bytes[self.bytes_read..self.bytes_read + val.1]);
        self.bytes_read += val.1;
        Ok(Ok(val.0))
    }

    /// read(), but trust that the length is correct and bounds checking will happen in deserialize.
    fn read_without_estimating<T>(&mut self) -> GenResult<Result<T, usize>>
    where
        T: Deserializable,
    {
        let val = T::deserialize(&self.bytes[self.bytes_read..])?;
        self.hasher
            .update(&self.bytes[self.bytes_read..self.bytes_read + val.1]);
        self.bytes_read += val.1;
        Ok(Ok(val.0))
    }

    fn finalize(self) -> u32 {
        self.hasher.finalize()
    }

    /// Sets the slice end to a given length: this prevents reading past the end of the length.
    fn set_slice_end(&mut self, length: usize) -> GenResult<()> {
        if length > self.bytes.len() {
            return Err(Error::NotEnoughBytes.into());
        }
        self.bytes = &self.bytes[..length];
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use chrono::{DateTime, TimeZone, Utc};

    use crate::{
        deserialize::Deserializable,
        serialize::Serializable,
        types::{event::Event, teststatus::TestStatus},
    };

    #[test]
    fn test_write_event() {
        let event = Event::new(TestStatus::InProgress)
            .test_id("A_test_id")
            .datetime(Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap())
            .unwrap()
            .tag("tag_a")
            .tag("tag_b")
            .build();

        let buffer = event.to_vec().unwrap();
        let out_event = Event::deserialize(&buffer).unwrap().0;
        assert_eq!(event, out_event);
    }

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

        let mut offset = 0;
        for event in [event, event_a].iter() {
            let (parsed_event, length) = Event::deserialize(&buffer[offset..]).unwrap();
            assert_eq!(*event, parsed_event);
            offset += length;
        }
    }

    #[test]
    fn test_reference_values() {
        #[track_caller]
        fn assert_reference(event: Event, buffer: &[u8]) {
            // We can parse the reference output
            let (parsed, length) = Event::deserialize(buffer).unwrap();
            assert_eq!(length, buffer.len());
            assert_eq!(parsed, event);
            // We can serialize and it matches the reference output
            let serialized = event.to_vec().unwrap();
            assert_eq!(serialized, buffer);
        }

        // Constants from the reference implementation
        let enumerated: &[u8] = b"\xb3)\x01\x0c\x03foo\x08U_\x1b";
        assert_reference(
            Event::new(TestStatus::Enumeration)
                .test_id("foo")
                .runnable()
                .build(),
            enumerated,
        );

        let inprogress: &[u8] = b"\xb3)\x02\x0c\x03foo\x8e\xc1-\xb5";
        assert_reference(
            Event::new(TestStatus::InProgress)
                .test_id("foo")
                .runnable()
                .build(),
            inprogress,
        );

        let success: &[u8] = b"\xb3)\x03\x0c\x03fooE\x9d\xfe\x10";
        assert_reference(
            Event::new(TestStatus::Success)
                .test_id("foo")
                .runnable()
                .build(),
            success,
        );

        let uxsuccess: &[u8] = b"\xb3)\x04\x0c\x03fooX\x98\xce\xa8";
        assert_reference(
            Event::new(TestStatus::UnexpectedSuccess)
                .test_id("foo")
                .runnable()
                .build(),
            uxsuccess,
        );

        let skip: &[u8] = b"\xb3)\x05\x0c\x03foo\x93\xc4\x1d\r";
        assert_reference(
            Event::new(TestStatus::Skipped)
                .test_id("foo")
                .runnable()
                .build(),
            skip,
        );

        let fail: &[u8] = b"\xb3)\x06\x0c\x03foo\x15Po\xa3";
        assert_reference(
            Event::new(TestStatus::Failed)
                .test_id("foo")
                .runnable()
                .build(),
            fail,
        );

        let xfail: &[u8] = b"\xb3)\x07\x0c\x03foo\xde\x0c\xbc\x06";
        assert_reference(
            Event::new(TestStatus::ExpectedFailure)
                .test_id("foo")
                .runnable()
                .build(),
            xfail,
        );

        let eof: &[u8] = b"\xb3!\x10\x08S\x15\x88\xdc";
        assert_reference(
            Event::new(TestStatus::Undefined)
                .end_of_file()
                .runnable()
                .build(),
            eof,
        );

        let file_content: &[u8] = b"\xb3!@\x13\x06barney\x03wooA5\xe3\x8c";
        assert_reference(
            Event::new(TestStatus::Undefined)
                .file_content("barney", b"woo")
                .runnable()
                .build(),
            file_content,
        );

        let mime: &[u8] = b"\xb3! #\x1aapplication/foo; charset=1x3Q\x15";
        assert_reference(
            Event::new(TestStatus::Undefined)
                .mime_type("application/foo; charset=1")
                .runnable()
                .build(),
            mime,
        );

        let timestamp: &[u8] = b"\xb3+\x03\x13<\x17T\xcf\x80\xaf\xc8\x03barI\x96>-";
        assert_reference(
            Event::new(TestStatus::Success)
                .test_id("bar")
                .datetime(DateTime::from_timestamp(1008161999, 45000).unwrap())
                .unwrap()
                .runnable()
                .build(),
            timestamp,
        );

        let route_code: &[u8] = b"\xb3-\x03\x13\x03bar\x06source\x9cY9\x19";
        assert_reference(
            Event::new(TestStatus::Success)
                .test_id("bar")
                .route_code("source")
                .runnable()
                .build(),
            route_code,
        );

        let runnable: &[u8] = b"\xb3(\x03\x0c\x03foo\xe3\xea\xf5\xa4";
        assert_reference(
            Event::new(TestStatus::Success).test_id("foo").build(),
            runnable,
        );

        // Tags have no defined order in the protocol. At least today in the Rust implementation, they are ordered as given/observed.
        let tag1: &[u8] = b"\xb3)\x80\x15\x03bar\x02\x03foo\x03barTHn\xb4";
        assert_reference(
            Event::new(TestStatus::Undefined)
                .test_id("bar")
                .tag("foo")
                .tag("bar")
                .runnable()
                .build(),
            tag1,
        );

        let tag2: &[u8] = b"\xb3)\x80\x15\x03bar\x02\x03bar\x03foo\xf8\xf1\x91o";
        assert_reference(
            Event::new(TestStatus::Undefined)
                .test_id("bar")
                .tag("bar")
                .tag("foo")
                .runnable()
                .build(),
            tag2,
        );
    }

    #[test]
    fn packet_length() {
        assert_eq!(12, Event::packet_length(11).unwrap().as_u32());
    }
}
