//! crate for various checksum algorithms
//!
//! This crate provides an API and set of implementations that can be
//! used to compute checksums for collections of bytes.
#![warn(missing_docs)]
#![warn(unsafe_code)]
#![no_std]

pub mod adler32;
pub mod crc;
pub mod crc_table;
pub mod fletcher16;

/// Checksum trait all checksum algorithms should implement
/// This provides several compute operations
///
/// There are multiple uses of the term check or checksum.  The term
/// in this context is a computation of a error-correcting code for a
/// set of data.
/// Sometimes a checksum is specifically used to refer to computation
/// of a checksum value that should equal zero.  That's not the
/// meaning here.  The Checksum trait provides an interface for
/// algorithms that can calculate checksums.
pub trait Checksum<T> {
    /// Compute a checksum over a u8 byte slice
    ///
    /// The Checksum API doesn't provide a finalize method.

    /// Every call to compute resets the state of the CRC to an
    /// initial state.  So calling it twice with the same parameters
    /// should yield the same result.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::checksum_tapestry::Checksum;
    /// use checksum_tapestry::adler32::Adler32;
    ///
    /// let expected: u32 = 0xe4801a6a;
    /// let string = "It's a tiny change to the code and not completely disgusting. - Bob Manchek";
    /// let data = string.as_bytes();
    /// let mut adler32 = Adler32::default();
    /// let result = adler32.compute(data);
    /// assert_eq!(result, expected);
    /// ```
    fn compute(&mut self, data: &[u8]) -> T;

    /// Perform a rolling update on the checksum.
    ///
    /// Update the checksum with a new byte, computing and returning
    /// the checksum.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::checksum_tapestry::Checksum;
    /// use checksum_tapestry::adler32::Adler32;
    ///
    /// let expected1: u32 = 0x004A004A;
    /// let expected2: u32 = 0x010800BE;
    /// let string = "It's a tiny change to the code and not completely disgusting. - Bob Manchek";
    /// let data = string.as_bytes();
    /// let mut adler32 = Adler32::default();
    /// let result = adler32.update(data[0]);
    /// assert_eq!(result, expected1);
    /// let result = adler32.update(data[1]);
    /// assert_eq!(result, expected2);
    /// ```
    fn update(&mut self, data: u8) -> T;

    /// Reset the checksum to the original state.
    /// This resets the checksum to the state it was in when it was
    /// created.
    /// If it was created with non-default parameters, those should be
    /// preserved.
    /// If an initial value was specified when originally creating the checksum,
    /// it should be preserved and initialized to that value.
    fn reset(&mut self);
}
