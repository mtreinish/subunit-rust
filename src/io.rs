//! Convienence functions for reading and writing subunit packets in different IO models

#[cfg(feature = "async")]
pub mod r#async;
#[cfg(feature = "sync")]
pub mod sync;
