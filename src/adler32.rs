//! Adler-32 checksums
//!
//! # Examples
//!
//! ```
//! use checksum_tapestry::Checksum;
//! use checksum_tapestry::adler32::Adler32;
//!
//! let expected: u32 = 0xE4801A6A;
//! let string = "It's a tiny change to the code and not completely disgusting. - Bob Manchek";
//! let data = string.as_bytes();
//! let mut adler32 = Adler32::default();
//! let result = adler32.compute(data);
//! assert_eq!(result, expected);
//! ```
use core::default::Default;

use crate::Checksum;

/// The data structure used for the Adler-32 checksums
/// Stores parameters and state
pub struct Adler32 {
    /// The modulus value to use for computing the checksum
    pub mod_adler: u32,
    /// Initial value of the checksum.
    /// This is saved so we can reset the checksum.
    initial: u32,
    /// Adler-32 checksum state
    a: u32,
    /// Adler-32 checksum state
    b: u32,
}

impl Adler32 {
    /// Create a new Adler32 checksum with the given modulus.
    /// and a starting value.
    ///
    /// # Examples
    ///
    /// ```
    /// use checksum_tapestry::Checksum;
    /// use checksum_tapestry::adler32::Adler32;
    ///
    /// let expected: u32 = 0x91e01de;
    /// let string = "123456789";
    /// let data = string.as_bytes();
    /// let mut adler32 = Adler32::new(65521, 1);
    /// let result = adler32.compute(data);
    ///
    /// assert_eq!(result, expected);
    /// ```
    ///
    /// ```
    /// use checksum_tapestry::Checksum;
    /// use checksum_tapestry::adler32::Adler32;
    ///
    /// let expected: u32 = 0x25AE5855;
    /// let string = "123456789";
    /// let data = string.as_bytes();
    /// let mut adler32 = Adler32::new(65521, 0x12345678);
    /// let result = adler32.compute(data);
    ///
    /// assert_eq!(result, expected);
    /// ```
    pub fn new(mod_adler: u32, initial: u32) -> Adler32 {
        Adler32 {
            mod_adler,
            initial,
            a: initial & 0xFFFF,
            b: initial >> 16,
        }
    }
}

impl Default for Adler32 {
    fn default() -> Adler32 {
        Adler32 {
            mod_adler: 65521,
            initial: 0x00000001,
            a: 1,
            b: 0,
        }
    }
}

impl Checksum<u32> for Adler32 {
    /// Compute an adler32 checksum
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
    fn compute(&mut self, data: &[u8]) -> u32 {
        for byte in data {
            self.update(*byte);
        }

        (self.b << 16) | self.a
    }

    /// From Wikipedia
    /// The formula used is:
    /// `A = 1 + data[0] + data[1] + ... + data[n] (mod 65521)`
    fn update(&mut self, data: u8) -> u32 {
        self.a = (self.a + (data as u32)) % self.mod_adler;
        self.b = (self.b + self.a) % self.mod_adler;

        (self.b << 16) | self.a
    }

    /// Reset the CRC
    fn reset(&mut self) {
        self.a = self.initial & 0xFFFF;
        self.b = self.initial >> 16;
    }
}

#[cfg(test)]
mod tests {
    use super::Adler32;
    use crate::Checksum;

    /// Test against Python 3 zlib module output
    #[test]
    fn test_python3_zlib_result() {
        let expected: u32 = 0x91e01de;
        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::default();

        let result = adler32.compute(data);
        assert_eq!(result, expected);
    }

    /// This test data is from the Go hash package
    #[test]
    fn byte_string_works() {
        let expected: u32 = 0xe4801a6a;
        let string = "It's a tiny change to the code and not completely disgusting. - Bob Manchek";
        let data = string.as_bytes();

        let mut adler32 = Adler32::default();

        let result = adler32.compute(data);
        assert_eq!(result, expected);
    }

    /// Test that a rolling update works
    /// This test data is from the Go hash package
    #[test]
    fn rolling_update_one_update_works() {
        let expected_first_update: u32 = 0x00620062;
        let string = "a";
        let data = string.as_bytes()[0];

        let mut adler32 = Adler32::default();

        let result = adler32.update(data);
        assert_eq!(result, expected_first_update);
    }

    /// Test that two rolling updates work
    /// This test data is from the Go hash package
    #[test]
    fn rolling_update_two_updates_works() {
        // Add the first byte, update the checksum
        let expected_first_update: u32 = 0x00620062;
        let string = "a";
        let data = string.as_bytes()[0];

        let mut adler32 = Adler32::default();

        let result = adler32.update(data);
        assert_eq!(result, expected_first_update);

        // Add another byte, update the checksum
        let expected_second_update: u32 = 0x012600c4;
        let string = "b";
        let data = string.as_bytes()[0];

        let result = adler32.update(data);
        assert_eq!(result, expected_second_update);
    }

    /// Test an Adler-32 created with new with the default parameters
    /// Verified against Python zlib
    #[test]
    fn test_new_with_default() {
        let expected: u32 = 0x91e01de;

        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::new(65521, 1);
        let result = adler32.compute(data);

        assert_eq!(result, expected);
    }

    /// Test an Adler-32 created with new with a 16-bit initial value
    /// Verified against Python zlib
    #[test]
    fn test_new_with_16_bit() {
        let expected: u32 = 0xACE91411;

        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::new(65521, 0x1234);
        let result = adler32.compute(data);

        assert_eq!(result, expected);
    }

    /// Test an Adler-32 created with new with a 32-bit initial value
    /// Verified against Python zlib
    #[test]
    fn test_new_with_32_bit() {
        let expected: u32 = 0x25AE5855;

        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::new(65521, 0x12345678);
        let result = adler32.compute(data);

        assert_eq!(result, expected);
    }

    /// Test reset with a checksum created with default values
    #[test]
    fn test_reset_with_default() {
        let expected: u32 = 0x91e01de;
        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::default();

        let result = adler32.compute(data);
        assert_eq!(result, expected);

        // Test after resetting
        adler32.reset();
        let result = adler32.compute(data);

        assert_eq!(result, expected);
    }

    /// Test reset with a checksum created with new with a 32-bit
    /// initial value
    #[test]
    fn test_reset_with_new_with_32_bit() {
        let expected: u32 = 0x25AE5855;

        let string = "123456789";
        let data = string.as_bytes();

        let mut adler32 = Adler32::new(65521, 0x12345678);
        let result = adler32.compute(data);

        assert_eq!(result, expected);

        // Test after resetting
        adler32.reset();
        let result = adler32.compute(data);

        assert_eq!(result, expected);
    }
}
