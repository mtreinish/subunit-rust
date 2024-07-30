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

//! Implementation of the Subunit protocol in Rust. For the protocol definition,
//! see the [Subunit Protocol
//! Specification](https://github.com/testing-cabal/subunit/blob/main/README.rst).
//! This crate contains both a v1 and v2 implementation of the protocol. v1 is
//! disabled by default but can be enabled via the `v1` feature.

pub mod types {
    pub mod event;
    pub mod eventfeatures;
    pub mod file;
    pub mod number;
    pub mod stream;
    pub mod teststatus;
    pub mod timestamp;
}

pub mod deserialize;
pub mod io;
pub mod serialize;
pub mod constants {
    pub static V2_SIGNATURE: u8 = 0xb3;
    pub static MAX_PACKET_LENGTH: u32 = 4 * 1024 * 1024;
    pub static MAX_NUMBER_VALUE: u32 = 0x3fffffff;
    pub static NUMBER_KIND_MASK: u8 = 0xc0;
    pub static NUMBER_VALUE_MASK: u8 = 0x3f;
    pub static VERSION2: u16 = 0x2000;
}
#[cfg(feature = "v1")]
pub mod v1;

use std::fmt::Debug;

use thiserror::Error as ThisError;

#[derive(ThisError)]
pub enum Error {
    #[error("Value is too large to encode")]
    TooLarge,
    #[error("Invalid packet header: size {} < header size {}", _0, _1)]
    LengthTooSmall(u32, u32),
    #[error("Internal logic error {}", _0)]
    Internal(String),
    #[error("Invalid UTF8")]
    InvalidUTF8Sequence,
    #[error("Not enough bytes")]
    NotEnoughBytes,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Bad version {:#x}", _0)]
    BadVersion(u16),
    #[error("CRC32 Mismatch measured: {:#02x} != stored: {:#02x}", _0, _1)]
    CRC32Mismatch(u32, u32),
    #[error("Invalid timestamp secs: {} nsecs: {}", _0, _1)]
    InvalidTimestamp(u32, u32),
    #[error("IO Error: {}", _0)]
    IO(#[from] std::io::Error),
    #[cfg(feature = "v1")]
    #[error("V1 Parsing error: {:?}", _0)]
    V1Parse(String),
}

#[cfg(feature = "v1")]
impl<I, O> From<winnow::error::ParseError<I, O>> for Error
where
    I: std::fmt::Debug,
    O: std::fmt::Debug,
{
    fn from(err: winnow::error::ParseError<I, O>) -> Self {
        Error::V1Parse(format!("{:?}", err))
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

type GenError = Box<dyn std::error::Error>;
type GenResult<T> = Result<T, GenError>;
