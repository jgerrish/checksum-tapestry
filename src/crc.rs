//! CRC checksums
//!
//! # Examples
//!
//! ```
//! use checksum_tapestry::crc::{BitWidth, CRCConfiguration, CRCEndianness, CRC};
//! use checksum_tapestry::Checksum;
//! let expected: u32 = 0xCBF43926;
//! let string = "123456789";
//! let data = string.as_bytes();
//! let mut crc32 = CRC::<u32>::new(CRCConfiguration::<u32>::new(
//!     "CRC-32/ISO-HDLC",
//!     BitWidth::ThirtyTwo,
//!     CRCEndianness::LSB,
//!     0x04C11DB7,
//!     true,
//!     Some(0xFFFFFFFF),
//!     Some(0xFFFFFFFF),
//! ));
//!
//! let result: u32 = crc32.compute(&data);
//! assert_eq!(result, expected);
//! ```
#![warn(missing_docs)]
#![warn(unsafe_code)]

use core::default::Default;

use crate::{
    crc_table::{build_table_16, build_table_32},
    Checksum,
};

/// We create a trait type here that lets us perform operations on
/// different width groups.
/// This is the pattern used in the crc-catalog crate.
pub trait Width: Sized + Copy + 'static {}

impl Width for u16 {}
impl Width for u32 {}

/// The CRC32 structure
pub struct CRC<'a, BITWIDTH: Width> {
    configuration: CRCConfiguration<'a, BITWIDTH>,
    /// The pre-computed values to speeed up computing the CRC
    pub table: [BITWIDTH; 256],

    /// state of the CRC for rolling checksums
    crc: BITWIDTH,
}

/// Configuration settings for CRC
/// This incorporates some advice from the parameter model described
/// in:
/// Williams, Ross N. "A Painless Guide to CRC Error Detection
/// Algorithms", Rocksoft Pty Ltd., 1993, crc_ross.pdf
///
/// It differs from that model in that a CRC endianness property is
/// used instead of relying solely on reflect in and reflect out.
/// Endianness is used in the same way as reflect in, but uses
/// Rust-style enumerations.
#[derive(Clone, Copy)]
pub struct CRCConfiguration<'a, BITWIDTH: Width> {
    /// The common or standard name of this CRC32 configuration
    #[allow(dead_code)]
    name: &'a str,
    /// The bit-width
    pub width: BitWidth,

    /// The bit-endianness.
    ///
    /// This parameter is equivalent to setting reflect_in to true.
    ///
    /// Setting this to CRCEndianness::LSB will cause the CRC
    /// calculations to behave as if reflect_in had been specified as
    /// true.
    ///
    /// Reflecting a binary value swaps the bits around the center, so
    /// 0b10110001 reflected would be 0b10001101 and
    /// 0b10001101 reflected would be 0b10110001
    ///
    /// Instead of reflecting the data as we process it, we can
    /// reflect the table we use for computation.
    pub endianness: CRCEndianness,

    /// The polynomial represented as an unsigned integer
    pub poly: BITWIDTH,

    /// "Reflect" the final value
    /// If this setting is true and the endianess is MSB, reflect the final value.
    /// For most CRCs, if the endianness is MSB, this is false
    /// and if the endianness is LSB, this is true.
    reflect_out: bool,

    /// Initial value of the checksum
    initial: BITWIDTH,

    /// Whether the final value should be XORed before returned, and what it should
    /// be XORed with.
    xor_out: Option<BITWIDTH>,
}

impl<'a> CRCConfiguration<'a, u16> {
    /// Create a new CRC32Configuration
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'a str,
        width: BitWidth,
        endianness: CRCEndianness,
        poly: u16,
        reflect_out: bool,
        initial: Option<u16>,
        xor_out: Option<u16>,
    ) -> CRCConfiguration<u16> {
        let initial = if let Some(i) = initial { i } else { 0x0000 };

        CRCConfiguration {
            name,
            width,
            endianness,
            poly,
            reflect_out,
            initial,
            xor_out,
        }
    }
}

impl CRCConfiguration<'_, u32> {
    /// Create a new CRC32Configuration
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        width: BitWidth,
        endianness: CRCEndianness,
        poly: u32,
        reflect_out: bool,
        initial: Option<u32>,
        xor_out: Option<u32>,
    ) -> CRCConfiguration<u32> {
        let initial = if let Some(i) = initial { i } else { 0x00000000 };

        CRCConfiguration {
            name,
            width,
            endianness,
            poly,
            reflect_out,
            initial,
            xor_out,
        }
    }
}

/// The bit-width of the CRC
#[derive(Clone, Copy)]
pub enum BitWidth {
    /// 3-bit
    Three = 3,
    /// 4-bit
    Four = 4,
    /// 7-bit
    Seven = 7,
    /// 8-bit
    Eight = 8,
    /// 12-bit
    Twelve = 12,
    /// 16-bit
    Sixteen = 16,
    /// 32-bit
    ThirtyTwo = 32,
}

/// CRC32 bit-endianness
#[derive(Clone, Copy)]
pub enum CRCEndianness {
    /// Most-significant bit first, big-endian
    MSB,
    /// Least-significant bit first, little-endian
    LSB,
}

impl<'a> CRC<'a, u32> {
    /// Create a new CRC
    #[allow(dead_code)]
    pub fn new(configuration: CRCConfiguration<'a, u32>) -> Self {
        // Work through how the CRC works, whether we need to incorporate
        // endianness into both the table generation and the computation
        // Endianness is related to the "reflection" parameter.
        let table = build_table_32(&configuration);

        let crc = CRC::<u32>::reset(&configuration);

        CRC {
            configuration,
            table,
            crc,
        }
    }

    /// Reset the CRC to the initial state
    /// Returns the CRC value
    /// It's not very RAII
    fn reset(configuration: &CRCConfiguration<'a, u32>) -> u32 {
        match configuration.endianness {
            CRCEndianness::LSB => {
                configuration.initial.reverse_bits() >> (32u8 - (configuration.width as u8))
            }
            CRCEndianness::MSB => configuration.initial << (32u8 - (configuration.width as u8)),
        }
    }
}

impl<'a> CRC<'a, u16> {
    /// Create a new CRC
    #[allow(dead_code)]
    pub fn new(configuration: CRCConfiguration<'a, u16>) -> Self {
        // Work through how the CRC works, whether we need to incorporate
        // endianness into both the table generation and the computation
        // Endianness is related to the "reflection" parameter.
        let table = build_table_16(&configuration);

        let crc = CRC::<u16>::reset(&configuration);

        CRC {
            configuration,
            table,
            crc,
        }
    }

    /// Reset the CRC to the initial state
    /// Returns the CRC value
    /// It's not very RAII
    fn reset(configuration: &CRCConfiguration<'a, u16>) -> u16 {
        match configuration.endianness {
            CRCEndianness::LSB => {
                configuration.initial.reverse_bits() >> (16u8 - (configuration.width as u8))
            }
            CRCEndianness::MSB => configuration.initial << (16u8 - (configuration.width as u8)),
        }
    }
}

impl<'a> Default for CRC<'a, u32> {
    fn default() -> Self {
        let poly: u32 = 0x04C11DB7;
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            poly,
            false,
            None,
            None,
        );

        CRC::<u32>::new(configuration)
    }
}

impl<'a> Default for CRC<'a, u16> {
    fn default() -> Self {
        let poly: u16 = 0x1021;
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16",
            BitWidth::Sixteen,
            CRCEndianness::MSB,
            poly,
            true,
            None,
            None,
        );

        CRC::<u16>::new(configuration)
    }
}

impl<'a> Checksum<u32> for CRC<'a, u32> {
    fn compute(&mut self, data: &[u8]) -> u32 {
        self.crc = CRC::<u32>::reset(&self.configuration);

        for byte in data {
            self.update(*byte);
        }

        if let CRCEndianness::MSB = self.configuration.endianness {
            if self.configuration.reflect_out {
                self.crc = self.crc.reverse_bits();
            }
        }
        if !self.configuration.reflect_out {
            self.crc >>= 32u8 - (self.configuration.width as u8);
        }

        if let Some(xor_out) = self.configuration.xor_out {
            self.crc ^ xor_out
        } else {
            self.crc
        }
    }

    fn update(&mut self, data: u8) -> u32 {
        // table is an array of 256 32-bit constants
        self.crc = match self.configuration.endianness {
            CRCEndianness::LSB => {
                let index: u32 = (self.crc ^ (data as u32)) & 0xFF;
                (self.crc >> 8) ^ self.table[index as usize]
            }
            CRCEndianness::MSB => {
                let index: u32 = ((self.crc >> 24) ^ (data as u32)) & 0xFF;
                (self.crc << 8) ^ self.table[index as usize]
            }
        };

        self.crc
    }
}

impl<'a> Checksum<u16> for CRC<'a, u16> {
    fn compute(&mut self, data: &[u8]) -> u16 {
        self.crc = CRC::<u16>::reset(&self.configuration);

        for byte in data {
            self.update(*byte);
        }

        if let CRCEndianness::MSB = self.configuration.endianness {
            if self.configuration.reflect_out {
                self.crc = self.crc.reverse_bits();
            }
        }
        if !self.configuration.reflect_out {
            self.crc >>= 16u8 - (self.configuration.width as u8);
        }

        if let Some(xor_out) = self.configuration.xor_out {
            self.crc ^ xor_out
        } else {
            self.crc
        }
    }

    fn update(&mut self, data: u8) -> u16 {
        // table is an array of 256 16-bit constants
        self.crc = match self.configuration.endianness {
            CRCEndianness::LSB => {
                let index = (self.crc ^ (data as u16)) & 0xFF;
                (self.crc >> 8) ^ self.table[index as usize]
            }
            CRCEndianness::MSB => {
                let index = ((self.crc >> 8) ^ (data as u16)) & 0xFF;
                (self.crc << 8) ^ self.table[index as usize]
            }
        };

        self.crc
    }
}

#[cfg(test)]
mod tests {
    use super::{BitWidth, CRCConfiguration, CRCEndianness, CRC};
    use crate::Checksum;

    /// Test CRC-3-GSM MSB
    #[test]
    fn crc_3_gsm_works() {
        let string = "123456789";
        let data = string.as_bytes();
        let mut crc3 = CRC::<u16>::new(CRCConfiguration::<u16>::new(
            "CRC-3/GSM",
            BitWidth::Three,
            CRCEndianness::MSB,
            0b011,
            false,
            None,
            Some(0b111),
        ));
        let expected: u16 = 0x4;

        let result = crc3.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/ISO-HDLC.
    /// This is the same algorithm used in the Python zlib module.
    #[test]
    fn crc32_iso_hdlc() {
        let expected: u32 = 0xCBF43926;
        let string = "123456789";
        let data = string.as_bytes();
        let mut crc32 = CRC::<u32>::new(CRCConfiguration::<u32>::new(
            "CRC-32/ISO-HDLC",
            BitWidth::ThirtyTwo,
            CRCEndianness::LSB,
            0x04C11DB7,
            true,
            Some(0xFFFFFFFF),
            Some(0xFFFFFFFF),
        ));

        let result: u32 = crc32.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-16/Genibus
    #[test]
    fn crc_16_genibus_works() {
        let expected: u16 = 0xD64E;
        let string = "123456789";
        let data = string.as_bytes();
        let mut crc = CRC::<u16>::new(CRCConfiguration::<u16>::new(
            "CRC-32/Genibus",
            BitWidth::Sixteen,
            CRCEndianness::MSB,
            0x1021,
            false,
            Some(0xFFFF),
            Some(0xFFFF),
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-12/UMTS
    #[test]
    fn crc_16_umts_works() {
        let expected: u16 = 0xDAF;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(CRCConfiguration::<u16>::new(
            "CRC-12/UMTS",
            BitWidth::Twelve,
            CRCEndianness::MSB,
            0x80F,
            true,
            None,
            None,
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/BZIP2
    #[test]
    fn crc_32_bzip2_works() {
        let expected: u32 = 0xFC891918;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(CRCConfiguration::<u32>::new(
            "CRC-32/MPEG-2",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            0x04C11DB7,
            false,
            Some(0xFFFFFFFF),
            Some(0xFFFFFFFF),
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/MPEG-2
    #[test]
    fn crc_32_mpeg2_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(CRCConfiguration::<u32>::new(
            "CRC-32/MPEG-2",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            0x04C11DB7,
            false,
            Some(0xFFFFFFFF),
            None,
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-16/KERMIT
    #[test]
    fn crc_16_kermit_works() {
        let expected: u16 = 0x2189;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(CRCConfiguration::<u16>::new(
            "CRC-16/KERMIT",
            BitWidth::Sixteen,
            CRCEndianness::LSB,
            0x1021,
            true,
            None,
            None,
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/iSCSI, also called CRC-32C (Castagnoli)
    #[test]
    fn crc_32_iscsi_works() {
        let expected: u32 = 0xE3069283;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(CRCConfiguration::<u32>::new(
            "CRC-32/iSCSI",
            BitWidth::ThirtyTwo,
            CRCEndianness::LSB,
            0x1EDC6F41,
            true,
            Some(0xFFFFFFFF),
            Some(0xFFFFFFFF),
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test calling compute twice works
    #[test]
    fn compute_called_twice_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(CRCConfiguration::<u32>::new(
            "CRC-32/MPEG-2",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            0x04C11DB7,
            false,
            Some(0xFFFFFFFF),
            None,
        ));

        let result = crc.compute(&data);
        assert_eq!(result, expected);

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }
}