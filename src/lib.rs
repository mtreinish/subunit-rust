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

extern crate byteorder;
extern crate chrono;
extern crate crc;

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::io::Read;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::prelude::*;
use crc::{Hasher32, crc32};

#[derive(Debug, Clone)]
pub struct SizeError;
#[derive(Debug, Clone)]
pub struct InvalidFlag;
#[derive(Debug, Clone)]
pub struct InvalidMask;

type GenError = Box<Error>;
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

    fn cause(&self) -> Option<&Error> {
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

    fn cause(&self) -> Option<&Error> {
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

    fn cause(&self) -> Option<&Error> {
        None
    }
}

fn flag_to_status(flag: u8) -> Result<String, InvalidFlag> {
    match flag {
        0x0 => return Result::Ok("".to_string()),
        0x1 => return Result::Ok("exists".to_string()),
        0x2 => return Result::Ok("inprogress".to_string()),
        0x3 => return Result::Ok("success".to_string()),
        0x4 => return Result::Ok("uxsuccess".to_string()),
        0x5 => return Result::Ok("skip".to_string()),
        0x6 => return Result::Ok("fail".to_string()),
        0x7 => return Result::Ok("xfail".to_string()),
        _ => return Result::Err(InvalidFlag),
    }
}

fn status_to_flag(status: &str) -> Result<u16, InvalidFlag> {
    if status == "" {
        return Result::Ok(0x0);
    } else if status == "exists" {
        return Result::Ok(0x1);
    } else if status == "inprogress" {
        return Result::Ok(0x2);
    } else if status == "success" {
        return Result::Ok(0x3);
    } else if status == "uxsuccess" {
        return Result::Ok(0x4);
    } else if status == "skip" {
        return Result::Ok(0x5);
    } else if status == "fail" {
        return Result::Ok(0x6);
    } else if status == "xfail" {
        return Result::Ok(0x7);
    } else {
        return Result::Err(InvalidFlag);
    }
}

fn flag_masks(masks: &str) -> Result<u16, InvalidMask> {
    match masks {
        "testId" => return Result::Ok(0x0800),
        "routeCode" => return Result::Ok(0x0400),
        "timestamp" => return Result::Ok(0x0200),
        "runnable" => return Result::Ok(0x0100),
        "tags" => return Result::Ok(0x0080),
        "mimeType" => return Result::Ok(0x0020),
        "eof" => return Result::Ok(0x0010),
        "fileContent" => return Result::Ok(0x0040),
        _ => return Result::Err(InvalidMask),
    }
}

fn write_number<T: Write>(value: u32, mut ret: T) -> Result<T, SizeError> {
    // The first two bits encode the size:
    // 00 = 1 byte
    // 01 = 2 bytes
    // 10 = 3 bytes
    // 11 = 4 bytes

    // 2^(8-2)
    if value < 64 {
        // Fits in one byte.
        ret.write_u8(value as u8);
    // 2^(16-2):
    } else if value < 16384 {
        // Fits in two bytes.
        // Set the size to 01.
        ret.write_u16::<BigEndian>(value as u16 | 0x4000);
    // 2^(24-2):
    } else if value < 4194304 {
        // Fits in three bytes.
        // Drop the two least significant bytes and set the size to 10.
        ret.write_u8(((value >> 16) | 0x80) as u8);
        ret.write_u16::<BigEndian>(value as u16 & 0xffff);
    // 2^(32-2):
    } else if value < 1073741824 {
        // Fits in four bytes.
        // Set the size to 11.
        ret.write_u32::<BigEndian>(value | 0xC0000000);
    } else {
        return Result::Err(SizeError);
    }
    return Result::Ok(ret);
}

fn write_utf8<T: Write>(string: &str, mut out: T) -> Result<T, SizeError> {
    out = write_number(string.len() as u32, out)?;
    out.write(string.as_bytes());
    return Result::Ok(out);
}

pub struct Event {
    status: Option<String>,
    test_id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    file_name: Option<String>,
    file_content: Option<Vec<u8>>,
    mime_type: Option<String>,
    route_code: Option<String>,
    tags: Option<Vec<String>>,
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
        let mut length;
        if (base_length <= 62) {
            length = base_length + 1;
        // 16383 - 2
        } else if (base_length <= 16381) {
            length = base_length + 2;
        // 4194303 - 3
        } else if (base_length <= 4194300) {
            length = base_length + 3;
        } else {
            panic!("The packet is too large");
        }

        // Write event to stream
        buffer.write_u8(SIGNATURE)?;
        buffer.write_u16::<BigEndian>(flags)?;
        buffer = write_number(length as u32, buffer)?;

        for n in timestamp {
            buffer.write_u8(n)?;
        }
        for n in test_id {
            buffer.write_u8(n)?;
        }
        for n in tags {
            buffer.write_u8(n)?;
        }
        for n in mime_type {
            buffer.write_u8(n)?;
        }
        for n in file_content {
            buffer.write_u8(n)?;
        }
        for n in routing_code {
            buffer.write_u8(n)?;
        }
        // Flush buffer into output and digest to calculate crc32
        let mut digest = crc32::Digest::new(crc32::IEEE);
        for n in buffer {
            digest.write(&[n]);
            writer.write_u8(n)?;
        }
        writer.write_u32::<BigEndian>(digest.sum32())?;
        return Result::Ok(writer);
    }
    fn make_routing_code(&self) -> GenResult<Vec<u8>> {
        let mut routing_code: Vec<u8> = Vec::new();
        if self.route_code.is_some() {
            routing_code = write_utf8(
                self.route_code.as_ref().unwrap(), routing_code)?;
        }
        return Result::Ok(routing_code);
    }

    fn make_file_content(&self) -> GenResult<Vec<u8>> {
        let mut file_content: Vec<u8> = Vec::new();
        if self.file_name.is_some() && self.file_content.is_some() {
            file_content = write_utf8(self.file_name.as_ref().unwrap(), file_content)?;
            let len = self.file_content.as_ref().unwrap().len();
            file_content = write_number(len as u32, file_content)?;
            for n in self.file_content.as_ref().unwrap() {
                file_content.write_u8(*n)?;
            }
        }
        return Result::Ok(file_content);
    }

    fn make_mime_type(&self) -> GenResult<Vec<u8>> {
        let mut mime_type: Vec<u8> = Vec::new();
        if self.mime_type.is_some() {
            mime_type = write_utf8(
                self.mime_type.as_ref().unwrap(), mime_type)?;
        }
        return Result::Ok(mime_type);
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
        return Result::Ok(tags);
    }

    fn make_test_id(&self) -> GenResult<Vec<u8>> {
        let mut test_id: Vec<u8> = Vec::new();
        if self.test_id.is_some() {
            let raw_id = self.test_id.as_ref().unwrap();
            test_id = write_utf8(raw_id, test_id)?;
        }
        return Result::Ok(test_id);
    }

    fn make_timestamp(&self) -> GenResult<Vec<u8>> {
        let mut timestamp: Vec<u8> = Vec::new();
        if self.timestamp.is_some() {
            let secs = self.timestamp.unwrap().timestamp() as u32;
            timestamp.write_u32::<BigEndian>(secs);
            let subsec_nanos = self.timestamp.unwrap().timestamp_subsec_nanos();
            timestamp = write_number(subsec_nanos, timestamp)?;
        }
        return Result::Ok(timestamp);
    }

    fn make_flags(&self) -> GenResult<u16> {
        let mut flags = 0x2000 as u16; // version 0x2
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
        return Result::Ok(flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
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
            route_code: None
        };
        let mut buffer: Vec<u8> = Vec::new();

        buffer = match event.write(buffer) {
            Result::Ok(buffer) => buffer,
            Result::Err(err) =>
                panic!("Error while generating subunit {}", err),
        };
    }
}
