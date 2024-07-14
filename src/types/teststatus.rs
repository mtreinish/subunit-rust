//! Test status enum and conversion to/from u16.

/// Status of a test case.
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L287)
///
/// This is not modelled as `Option<TestStatus>` because it just lines up a bit
/// more nicely - e.g. we can implement `From<u16>` for `TestStatus` when we can't
/// implement it for `Option<TestStatus>`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum TestStatus {
    /// The test case status is undefined or the event was received outside of a test case
    Undefined = 0x0,
    /// The test was enumerated but not run
    Enumeration = 0x1,
    /// The test is in progress
    InProgress = 0x2,
    /// The test was successful
    Success = 0x3,
    /// The test was successful but was expected to fail
    UnexpectedSuccess = 0x4,
    /// The test was skipped
    Skipped = 0x5,
    /// The test failed
    Failed = 0x6,
    /// The test failed as was expected
    ExpectedFailure = 0x7,
}

impl From<u16> for TestStatus {
    fn from(value: u16) -> Self {
        match value & 0x7 {
            0x0 => Self::Undefined,
            0x1 => Self::Enumeration,
            0x2 => Self::InProgress,
            0x3 => Self::Success,
            0x4 => Self::UnexpectedSuccess,
            0x5 => Self::Skipped,
            0x6 => Self::Failed,
            _ /* 0x7 */ => Self::ExpectedFailure,
        }
    }
}
