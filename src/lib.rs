// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::cargo)]
#![allow(clippy::unreadable_literal)]

extern crate byteorder;
extern crate chrono;
extern crate crc32fast;

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;

#[derive(Debug, Clone)]
pub struct SizeError;
#[derive(Debug, Clone)]
pub struct InvalidFlag;
#[derive(Debug, Clone)]
pub struct InvalidMask;

type GenError = Box<dyn Error>;
type GenResult<T> = Result<T, GenError>;

const SIGNATURE: u8 = 0xb3;

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Value is too large to encode")
    }
}

impl Error for SizeError {
    fn description(&self) -> &str {
        "Value is too large to encode"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl fmt::Display for InvalidMask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mask code is invalid")
    }
}

impl Error for InvalidMask {
    fn description(&self) -> &str {
        "Mask code is valid"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl fmt::Display for InvalidFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Flag code is invalid")
    }
}

impl Error for InvalidFlag {
    fn description(&self) -> &str {
        "Flag code is invalid"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

fn flag_to_status(flag: u8) -> Result<String, InvalidFlag> {
    match flag {
        0x0 => Result::Ok("".to_string()),
        0x1 => Result::Ok("exists".to_string()),
        0x2 => Result::Ok("inprogress".to_string()),
        0x3 => Result::Ok("success".to_string()),
        0x4 => Result::Ok("uxsuccess".to_string()),
        0x5 => Result::Ok("skip".to_string()),
        0x6 => Result::Ok("fail".to_string()),
        0x7 => Result::Ok("xfail".to_string()),
        _ => Result::Err(InvalidFlag),
    }
}

fn status_to_flag(status: &str) -> Result<u16, InvalidFlag> {
    if status.is_empty() {
        Result::Ok(0x0)
    } else if status == "exists" {
        Result::Ok(0x1)
    } else if status == "inprogress" {
        Result::Ok(0x2)
    } else if status == "success" {
        Result::Ok(0x3)
    } else if status == "uxsuccess" {
        Result::Ok(0x4)
    } else if status == "skip" {
        Result::Ok(0x5)
    } else if status == "fail" {
        Result::Ok(0x6)
    } else if status == "xfail" {
        Result::Ok(0x7)
    } else {
        Result::Err(InvalidFlag)
    }
}

fn flag_masks(masks: &str) -> Result<u16, InvalidMask> {
    match masks {
        "testId" => Result::Ok(0x0800),
        "routeCode" => Result::Ok(0x0400),
        "timestamp" => Result::Ok(0x0200),
        "runnable" => Result::Ok(0x0100),
        "tags" => Result::Ok(0x0080),
        "mimeType" => Result::Ok(0x0020),
        "eof" => Result::Ok(0x0010),
        "fileContent" => Result::Ok(0x0040),
        _ => Result::Err(InvalidMask),
    }
}

fn flags_to_masks(flags: u16) -> GenResult<HashSet<String>> {
    let static_flags: [u16; 8] = [
        0x0800, 0x0400, 0x0200, 0x0100, 0x0080, 0x0020, 0x0010, 0x0040,
    ];
    let mut masks: HashSet<String> = HashSet::new();
    for flag in static_flags.iter() {
        if flags & *flag != 0 {
            if *flag == 0x0800 {
                masks.insert("testId".to_string());
            } else if *flag == 0x0400 {
                masks.insert("routeCode".to_string());
            } else if *flag == 0x0200 {
                masks.insert("timestamp".to_string());
            } else if *flag == 0x0100 {
                masks.insert("runnable".to_string());
            } else if *flag == 0x0080 {
                masks.insert("tags".to_string());
            } else if *flag == 0x0020 {
                masks.insert("mimeType".to_string());
            } else if *flag == 0x0010 {
                masks.insert("eof".to_string());
            } else if *flag == 0x0040 {
                masks.insert("fileContent".to_string());
            }
        }
    }
    Result::Ok(masks)
}

fn write_number<T: Write>(value: u32, mut ret: T) -> GenResult<T> {
    // The first two bits encode the size:
    // 00 = 1 byte
    // 01 = 2 bytes
    // 10 = 3 bytes
    // 11 = 4 bytes

    // 2^(8-2)
    if value < 64 {
        // Fits in one byte.
        ret.write_u8(value as u8)?
    // 2^(16-2):
    } else if value < 16384 {
        // Fits in two bytes.
        // Set the size to 01.
        ret.write_u16::<BigEndian>(value as u16 | 0x4000)?
    // 2^(24-2):
    } else if value < 4194304 {
        // Fits in three bytes.
        // Drop the two least significant bytes and set the size to 10.
        ret.write_u8(((value >> 16) | 0x80) as u8)?;
        ret.write_u16::<BigEndian>(value as u16)?;
    // 2^(32-2):
    } else if value < 1073741824 {
        // Fits in four bytes.
        // Set the size to 11.
        ret.write_u32::<BigEndian>(value | 0xC0000000)?;
    } else {
        return Result::Err(Box::new(SizeError));
    }
    Result::Ok(ret)
}

fn write_utf8<T: Write>(string: &str, mut out: T) -> GenResult<T> {
    out = write_number(string.len() as u32, out)?;
    out.write_all(string.as_bytes())?;
    Result::Ok(out)
}

pub fn read_number(reader: &mut Cursor<Vec<u8>>) -> GenResult<u32> {
    let first = reader.read_u8()?;
    // Get 2 first bits for prefix
    let number_type = first & 0xc0;
    // Get last 6 bits for first octet
    let mut value = u32::from(first) & 0x3f;
    // 0b00, 1 octet
    if number_type == 0x00 {
        Result::Ok(value)
    // 0b01, 2octets
    } else if number_type == 0x40 {
        let suffix = reader.read_u8()?;
        value = (value << 8) | u32::from(suffix);
        Result::Ok(value)
    // 0b10, 3 octets
    } else if number_type == 0x80 {
        let suffix = reader.read_u16::<BigEndian>()?;
        value = (value << 16) | u32::from(suffix);
        Result::Ok(value)
    // 0b11, 4 octets
    } else {
        let suffix = reader.read_u32::<BigEndian>()?;
        value = (value << 24) | suffix;
        Result::Ok(value)
    }
}

fn read_utf8(reader: &mut Cursor<Vec<u8>>) -> GenResult<String> {
    let length = read_number(reader)?;
    let mut bytes: Vec<u8> = Vec::new();
    for _i in 0..length {
        let byte = reader.read_u8()?;
        bytes.push(byte)
    }
    let output = String::from_utf8(bytes)?;
    Result::Ok(output)
}

fn read_packet(cursor: &mut Cursor<Vec<u8>>) -> GenResult<Event> {
    let start_position = cursor.position();
    let sig = cursor.read_u8()?;
    let flags = cursor.read_u16::<BigEndian>()?;
    let packet_length = read_number(cursor)?;
    if sig != SIGNATURE {
        panic!("Invalid signature");
    }
    let status = flag_to_status((flags & 0x0007) as u8)?;
    let masks = flags_to_masks(flags)?;

    let timestamp = if masks.contains("timestamp") {
        let seconds = cursor.read_u32::<BigEndian>()?;
        let nanos = read_number(cursor)?;
        Some(Utc.timestamp(i64::from(seconds), nanos))
    } else {
        None
    };
    let test_id = if masks.contains("testId") {
        let id = read_utf8(cursor)?;
        Some(id)
    } else {
        None
    };
    let tags = if masks.contains("tags") {
        let count = read_number(cursor)?;
        let mut tags_vec: Vec<String> = Vec::new();
        for _i in 0..count {
            let tag = read_utf8(cursor)?;
            tags_vec.push(tag);
        }
        Some(tags_vec)
    } else {
        None
    };
    let mime_type = if masks.contains("mimeType") {
        let mime = read_utf8(cursor)?;
        Some(mime)
    } else {
        None
    };
    let file_content;
    let file_name;
    if masks.contains("fileContent") {
        let name = read_utf8(cursor)?;
        file_name = Some(name);
        let file_length = read_number(cursor)?;
        let mut content: Vec<u8> = Vec::new();
        for _i in 0..file_length {
            let byte = cursor.read_u8()?;
            content.push(byte);
        }
        file_content = Some(content);
    } else {
        file_content = None;
        file_name = None;
    }

    let route_code = if masks.contains("routeCode") {
        let code = read_utf8(cursor)?;
        Some(code)
    } else {
        None
    };
    let _crc32 = cursor.read_u32::<BigEndian>()?;
    let end_position = cursor.position();
    if u64::from(packet_length) != (end_position - start_position) {
        panic!("Packet length doesn't match");
    }

    let event = Event {
        status: Some(status),
        test_id,
        timestamp,
        tags,
        file_content,
        file_name,
        mime_type,
        route_code,
    };
    Result::Ok(event)
}

pub fn parse_subunit<T: Read>(mut reader: T) -> GenResult<Vec<Event>> {
    let mut output: Vec<Event> = Vec::new();
    let mut contents: Vec<u8> = Vec::new();
    reader.read_to_end(&mut contents)?;
    let stream_length = contents.len() as u64;
    let cursor = &mut Cursor::new(contents);
    while cursor.position() < stream_length {
        let packet = read_packet(cursor)?;
        output.push(packet);
    }
    Result::Ok(output)
}

pub struct Event {
    pub status: Option<String>,
    pub test_id: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub file_name: Option<String>,
    pub file_content: Option<Vec<u8>>,
    pub mime_type: Option<String>,
    pub route_code: Option<String>,
    pub tags: Option<Vec<String>>,
}

impl Event {
    pub fn write<T: Write>(&mut self, mut writer: T) -> GenResult<T> {
        //  PACKET = SIGNATURE FLAGS PACKET_LENGTH TIMESTAMP? TESTID? TAGS?
        //           MIME? FILECONTENT? ROUTING_CODE? CRC32
        let flags = self.make_flags()?;
        let timestamp = self.make_timestamp()?;
        let test_id = self.make_test_id()?;
        let tags = self.make_tags()?;
        let mime_type = self.make_mime_type()?;
        let file_content = self.make_file_content()?;
        let routing_code = self.make_routing_code()?;

        let mut buffer: Vec<u8> = Vec::new();
        let mut body_length = timestamp.len() + test_id.len() + tags.len();
        body_length += mime_type.len() + file_content.len();
        body_length += routing_code.len();
        // baseLength = header (minus variant length) + body + crc32
        let base_length = 3 + body_length + 4;
        // length of length depends on baseLength and its own length
        // 63 - 1
        let length;
        if base_length <= 62 {
            length = base_length + 1;
        // 16383 - 2
        } else if base_length <= 16381 {
            length = base_length + 2;
        // 4194303 - 3
        } else if base_length <= 4194300 {
            length = base_length + 3;
        } else {
            panic!("The packet is too large");
        }

        // Write event to stream
        buffer.write_u8(SIGNATURE)?;
        buffer.write_u16::<BigEndian>(flags)?;
        buffer = write_number(length as u32, buffer)?;

        buffer.write_all(&timestamp)?;
        buffer.write_all(&test_id)?;
        buffer.write_all(&tags)?;
        buffer.write_all(&mime_type)?;
        buffer.write_all(&file_content)?;
        buffer.write_all(&routing_code)?;
        // Flush buffer into output and digest to calculate crc32
        let checksum = crc32fast::hash(&buffer);
        writer.write_all(&buffer)?;
        writer.write_u32::<BigEndian>(checksum)?;
        Result::Ok(writer)
    }
    fn make_routing_code(&self) -> GenResult<Vec<u8>> {
        let mut routing_code: Vec<u8> = Vec::new();
        if self.route_code.is_some() {
            routing_code = write_utf8(self.route_code.as_ref().unwrap(), routing_code)?;
        }
        Result::Ok(routing_code)
    }

    fn make_file_content(&self) -> GenResult<Vec<u8>> {
        let mut file_content: Vec<u8> = Vec::new();
        if let Some(file_name) = self.file_name.as_ref() {
            if let Option::Some(ref body) = self.file_content {
                file_content = write_utf8(file_name, file_content)?;
                let len = self.file_content.as_ref().unwrap().len();
                file_content = write_number(len as u32, file_content)?;
                file_content.write_all(body)?;
            }
        }
        Result::Ok(file_content)
    }

    fn make_mime_type(&self) -> GenResult<Vec<u8>> {
        let mut mime_type: Vec<u8> = Vec::new();
        if self.mime_type.is_some() {
            mime_type = write_utf8(self.mime_type.as_ref().unwrap(), mime_type)?;
        }
        Result::Ok(mime_type)
    }

    fn make_tags(&self) -> GenResult<Vec<u8>> {
        let mut tags: Vec<u8> = Vec::new();
        if self.tags.is_some() {
            let len = self.tags.as_ref().unwrap().len();
            tags = write_number(len as u32, tags)?;
            for tag in self.tags.as_ref().unwrap() {
                tags = write_utf8(tag, tags)?;
            }
        }
        Result::Ok(tags)
    }

    fn make_test_id(&self) -> GenResult<Vec<u8>> {
        let mut test_id: Vec<u8> = Vec::new();
        if self.test_id.is_some() {
            let raw_id = self.test_id.as_ref().unwrap();
            test_id = write_utf8(raw_id, test_id)?;
        }
        Result::Ok(test_id)
    }

    fn make_timestamp(&self) -> GenResult<Vec<u8>> {
        let mut timestamp: Vec<u8> = Vec::new();
        if self.timestamp.is_some() {
            let secs = self.timestamp.unwrap().timestamp() as u32;
            timestamp.write_u32::<BigEndian>(secs)?;
            let subsec_nanos = self.timestamp.unwrap().timestamp_subsec_nanos();
            timestamp = write_number(subsec_nanos, timestamp)?;
        }
        Result::Ok(timestamp)
    }

    fn make_flags(&self) -> GenResult<u16> {
        let mut flags = 0x2000_u16; // version 0x2
        if self.status.is_some() {
            flags |= status_to_flag(self.status.as_ref().unwrap())?;
        }

        if self.timestamp.is_some() {
            flags |= flag_masks("timestamp")?;
        }
        if self.test_id.is_some() {
            flags |= flag_masks("testId")?;
        }
        if self.tags.is_some() {
            flags |= flag_masks("tags")?;
        }
        if self.mime_type.is_some() {
            flags |= flag_masks("mimeType")?;
        }
        if self.file_name.is_some() && self.file_content.is_some() {
            flags |= flag_masks("fileContent")?;
        }
        if self.route_code.is_some() {
            flags |= flag_masks("routeCode")?;
        }
        Result::Ok(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_event() {
        let mut event = Event {
            status: Some("inprogress".to_string()),
            test_id: Some("A_test_id".to_string()),
            timestamp: Some(Utc.ymd(2014, 7, 8).and_hms(9, 10, 11)),
            tags: Some(vec!["tag_a".to_string(), "tag_b".to_string()]),
            file_content: None,
            file_name: None,
            mime_type: None,
            route_code: None,
        };
        let mut buffer: Vec<u8> = Vec::new();
        //        use std::fs::File;
        //        let mut buffer = File::create("/tmp/test.subunit").unwrap();

        buffer = match event.write(buffer) {
            Result::Ok(buffer) => buffer,
            Result::Err(err) => panic!("Error while generating subunit {}", err),
        };
        let cursor = Cursor::new(buffer);
        let out_events = parse_subunit(cursor);
        let out_event = out_events.unwrap().pop().unwrap();
        assert_eq!(event.test_id, out_event.test_id);
        assert_eq!(event.status, out_event.status);
        assert_eq!(event.timestamp, out_event.timestamp);
        assert_eq!(event.tags, out_event.tags);
        assert_eq!(event.file_content, out_event.file_content);
        assert_eq!(event.file_name, out_event.file_name);
        assert_eq!(event.mime_type, out_event.mime_type);
        assert_eq!(event.route_code, out_event.route_code);
    }
    #[test]
    fn test_write_full_test_event_with_file_content() {
        let mut event = Event {
            status: Some("inprogress".to_string()),
            test_id: Some("A_test_id".to_string()),
            timestamp: Some(Utc.ymd(2014, 7, 8).and_hms(9, 10, 11)),
            tags: Some(vec!["tag_a".to_string(), "tag_b".to_string()]),
            file_content: Some("stdout content".to_string().into_bytes()),
            file_name: Some("stdout:''".to_string()),
            mime_type: Some("text/plain;charset=utf8".to_string()),
            route_code: None,
        };
        let mut event_a = Event {
            status: Some("fail".to_string()),
            test_id: Some("A_test_id".to_string()),
            timestamp: Some(Utc.ymd(2014, 7, 8).and_hms(9, 12, 1)),
            tags: Some(vec!["tag_a".to_string(), "tag_b".to_string()]),
            file_content: None,
            file_name: None,
            mime_type: None,
            route_code: None,
        };
        let mut buffer: Vec<u8> = Vec::new();
        //        use std::fs::File;
        //        let mut buffer = File::create("/tmp/test2.subunit").unwrap();

        buffer = match event.write(buffer) {
            Result::Ok(buffer) => buffer,
            Result::Err(err) => panic!("Error while generating subunit {}", err),
        };
        buffer = match event_a.write(buffer) {
            Result::Ok(buffer) => buffer,
            Result::Err(err) => panic!("Error while generating subunit {}", err),
        };
        let cursor = Cursor::new(buffer);
        let mut out_events = parse_subunit(cursor).unwrap();
        // Parse last packet
        let out_event_a = out_events.pop().unwrap();
        assert_eq!(event_a.test_id, out_event_a.test_id);
        assert_eq!(event_a.status, out_event_a.status);
        assert_eq!(event_a.timestamp, out_event_a.timestamp);
        assert_eq!(event_a.tags, out_event_a.tags);
        assert_eq!(event_a.file_content, out_event_a.file_content);
        assert_eq!(event_a.file_name, out_event_a.file_name);
        assert_eq!(event_a.mime_type, out_event_a.mime_type);
        assert_eq!(event_a.route_code, out_event_a.route_code);
        // Parse first packet
        let out_event = out_events.pop().unwrap();
        assert_eq!(event.test_id, out_event.test_id);
        assert_eq!(event.status, out_event.status);
        assert_eq!(event.timestamp, out_event.timestamp);
        assert_eq!(event.tags, out_event.tags);
        assert_eq!(event.file_content, out_event.file_content);
        assert_eq!(event.file_name, out_event.file_name);
        assert_eq!(event.mime_type, out_event.mime_type);
        assert_eq!(event.route_code, out_event.route_code);
    }
}
