//! Fletcher-16 checksums
//!
//! # Examples
//!
//! ```
//! use checksum_tapestry::fletcher16::Fletcher16;
//! use checksum_tapestry::Checksum;
//!
//! let expected: u16 = 0xC8F0;
//! let string = "abcde";
//! let data = string.as_bytes();
//! let mut fletcher = Fletcher16::default();
//!
//! let result: u16 = fletcher.compute(data).try_into().unwrap();
//!
//! assert_eq!(result, expected);
//! ```
use core::default::Default;

use crate::Checksum;

/// The data structure used for the Fletcher-16 checksum
pub struct Fletcher16 {
    /// The modulus to use for calculating the checksum.
    /// Usually 255 for Fletcher16
    pub modulus: u8,

    c0: u16,
    c1: u16,
}

impl Default for Fletcher16 {
    fn default() -> Fletcher16 {
        Fletcher16 {
            modulus: 255,
            c0: 0,
            c1: 0,
        }
    }
}

impl Checksum<u16> for Fletcher16 {
    fn compute(&mut self, data: &[u8]) -> u16 {
        for byte in data {
            self.update(*byte);
        }

        (self.c1 << 8) | self.c0
    }

    fn update(&mut self, data: u8) -> u16 {
        self.c0 = (self.c0 + (data as u16)) % (self.modulus as u16);
        self.c1 = (self.c1 + self.c0) % (self.modulus as u16);

        (self.c1 << 8) | self.c0
    }

    fn reset(&mut self) {
        self.c0 = 0;
        self.c1 = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::Fletcher16;
    use crate::Checksum;

    /// "abcde" -> 51440 (0xC8F0)
    /// From Wikipedia: https://en.wikipedia.org/w/index.php?title=Fletcher%27s_checksum&action=edit&section=17
    /// Also validated against Dr. Dobb's implementation:
    /// https://www.drdobbs.com/article/print?articleId=184408761&siteSectionName=database
    #[test]
    fn fletcher16_test_one_works() {
        let expected: u16 = 0xC8F0;
        let string = "abcde";
        let data = string.as_bytes();
        let mut fletcher = Fletcher16::default();

        let result: u16 = fletcher.compute(data).try_into().unwrap();

        assert_eq!(result, expected);
    }

    /// "abcdef" -> 8279 (0x2057)
    /// From Wikipedia: https://en.wikipedia.org/w/index.php?title=Fletcher%27s_checksum&action=edit&section=17
    /// Also validated against Dr. Dobb's implementation:
    /// https://www.drdobbs.com/article/print?articleId=184408761&siteSectionName=database
    #[test]
    fn fletcher16_test_two_works() {
        let expected: u16 = 0x2057;
        let string = "abcdef";
        let data = string.as_bytes();
        let mut fletcher = Fletcher16::default();

        let result: u16 = fletcher.compute(data).try_into().unwrap();

        assert_eq!(result, expected);
    }

    /// "abcdefgh" -> 1575 (0x0627)
    /// From Wikipedia: https://en.wikipedia.org/w/index.php?title=Fletcher%27s_checksum&action=edit&section=17
    /// Also validated against Dr. Dobb's implementation:
    /// https://www.drdobbs.com/article/print?articleId=184408761&siteSectionName=database
    #[test]
    fn fletcher16_test_three_works() {
        let expected: u16 = 0x0627;
        let string = "abcdefgh";
        let data = string.as_bytes();
        let mut fletcher = Fletcher16::default();

        let result: u16 = fletcher.compute(data).try_into().unwrap();

        assert_eq!(result, expected);
    }

    /// A test case that wraps past 0xFFFF
    /// Verified against Dr. Dobb's implementation:
    /// https://www.drdobbs.com/article/print?articleId=184408761&siteSectionName=database
    #[test]
    fn fletcher16_16_bit_wrap() {
        let expected: u16 = 0xA587;
        let data: [u8; 400] = [0xA8; 400];

        let mut fletcher = Fletcher16::default();

        let result: u16 = fletcher.compute(&data).try_into().unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn fletcher16_reset_with_default_works() {
        let expected: u16 = 0xC8F0;
        let string = "abcde";
        let data = string.as_bytes();
        let mut fletcher = Fletcher16::default();

        let result: u16 = fletcher.compute(data).try_into().unwrap();
        assert_eq!(result, expected);

        fletcher.reset();
        let result: u16 = fletcher.compute(data).try_into().unwrap();
        assert_eq!(result, expected);
    }
}
