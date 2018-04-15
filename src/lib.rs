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
use crc::crc32;

#[derive(Debug, Clone)]
pub struct SizeError;
#[derive(Debug, Clone)]
pub struct OverSizeError;
#[derive(Debug, Clone)]
pub struct InvalidFlag;
#[derive(Debug, Clone)]
pub struct InvalidMask;

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Value must be greater than zero")
    }
}

impl Error for SizeError {
    fn description(&self) -> &str {
        "Value must be greater than zero"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl fmt::Display for OverSizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Value is too large to encode")
    }
}

impl Error for OverSizeError {
    fn description(&self) -> &str {
        "Value is too large to encode"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}



fn flagToStatus(flag: u8) -> Result<String, InvalidFlag> {
  match flag {
    0x0 => return Result::Ok("".to_string()),
    0x1 => return Result::Ok("exists".to_string()),
    0x2 => return Result::Ok("inprogress".to_string()),
    0x3 => return Result::Ok("success".to_string()),
    0x4 => return Result::Ok("uxsuccess".to_string()),
    0x5 => return Result::Ok("skip".to_string()),
    0x6 => return Result::Ok("fail".to_string()),
    0x7 => return Result::Ok("xfail".to_string()),
    _ => return Result::Err(InvalidFlag)
  }
}

fn statusToFlag(status: String) -> Result<u8, InvalidFlag> {
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

fn flagMasks(masks: &str) -> Result<u8, InvalidMask> {
  match masks {
    "testId" => return Result::Ok(0x0800),
    "routeCode" => return Result::Ok(0x0400),
    "timestamp" => return Result::Ok(0x0200),
    "runnable" => return Result::Ok(0x0100),
    "tags" => return Result::Ok(0x0080),
    "mimeType" => return Result::Ok(0x0020),
    "eof" => return Result::Ok(0x0010),
    "fileContent" => return Result::Ok(0x0040),
    _ => return Result::Err(InvalidMask)
  }
}

fn writeNumber<T: Write>(value: u32, mut ret: T) -> Result<T, SizeError>{
    // The first two bits encode the size:
    // 00 = 1 byte
    // 01 = 2 bytes
    // 10 = 3 bytes
    // 11 = 4 bytes
    if value < 0 {
        return Result::Err(SizeError);
    }

    if value < 64 { // 2^(8-2)
        // Fits in one byte.
        ret.write_u8(value as u8);
    } else if value < 16384 { // 2^(16-2)
        // Fits in two bytes.
        // Set the size to 01.
        ret.write_u16::<BigEndian>(value as u16 | 0x4000);
    } else if value < 4194304 { // 2^(24-2)
        // Fits in three bytes.
        // Drop the two least significant bytes and set the size to 10.
        ret.write_u8(((value >> 16) | 0x80) as u8);
        ret.write_u16::<BigEndian>(value as u16 & 0xffff);
    } else if value < 1073741824 { // 2^(32-2):
        // Fits in four bytes.
        // Set the size to 11.
        ret.write_u32::<BigEndian>(value | 0xC0000000);
    } else {
        return Result::Err(SizeError);
    }
    return Result::Ok(ret);
}

fn writeUtf8<T: Write>(string: String, mut out: T) -> Result<T, SizeError>{
    out = writeNumber(string.len() as u32, out)?;
    out.write(string.as_bytes());
    return Result::Ok(out);
}

struct Event {
    status: String,
    testID: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    fileName: Option<String>,
    fileContent: Option<Vec<u32>>,
    mimeType: Option<String>,
    routeCode: Option<String>,
    tags: Option<Vec<String>>,
}

struct packetPart {
    bytes: Vec<u32>,
    err: Error
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn test_write_number_8(){

    }
}
