//! Event feature and conversion to/from u16.

use enumset::EnumSetType;

/// Features for a subunit event
/// [Docs](https://github.com/testing-cabal/subunit/blob/fc698775674fcbdb9fcc8286d8358c7185647db4/README.rst?plain=1#L262)
#[derive(EnumSetType, Debug)]
// Note: the discriminants are the bit index (per
// `https://docs.rs/enumset/latest/enumset/struct.EnumSet.html#numeric-representation`),
// rather than the actual mask value : see
// `https://github.com/Lymia/enumset/issues/32`
#[enumset(repr = "u16", serialize_repr = "u16")]
pub enum EventFeatures {
    /// Must be zero in version 2.
    Reserved = 3, // 0x0008,
    /// EOF marker.
    EndOfFile = 4, // 0x0010,
    /// File MIME type is present.
    FileMimeType = 5, // 0x0020,
    /// File content is present.
    FileContent = 6, // 0x0040,
    /// Tags are present.
    Tags = 7, // 0x0080,
    /// Test is 'runnable'.
    Runnable = 8, // 0x0100,
    /// Timestamp present.
    Timestamp = 9, // 0x0200,
    /// Routing code present.
    RoutingCode = 10, // 0x0400,
    /// Test id present.
    TestId = 11, // 0x0800,
}

#[cfg(test)]
mod test {
    use super::EventFeatures;
    use enumset::{enum_set, EnumSet};

    #[test]
    fn bit_representation() {
        assert_eq!(enum_set! {EventFeatures::Reserved}.as_repr(), 0x0008);
        assert_eq!(enum_set! {EventFeatures::EndOfFile}.as_repr(), 0x0010);
        assert_eq!(enum_set! {EventFeatures::FileMimeType}.as_repr(), 0x0020);
        assert_eq!(enum_set! {EventFeatures::FileContent}.as_repr(), 0x0040);
        assert_eq!(enum_set! {EventFeatures::Tags}.as_repr(), 0x0080);
        assert_eq!(enum_set! {EventFeatures::Runnable}.as_repr(), 0x0100);
        assert_eq!(enum_set! {EventFeatures::Timestamp}.as_repr(), 0x0200);
        assert_eq!(enum_set! {EventFeatures::RoutingCode}.as_repr(), 0x0400);
        assert_eq!(enum_set! {EventFeatures::TestId}.as_repr(), 0x0800);
        // And a representative reverse test
        assert_eq!(
            EnumSet::<EventFeatures>::from_repr(0x0800),
            enum_set! {EventFeatures::TestId}
        );
    }
}
