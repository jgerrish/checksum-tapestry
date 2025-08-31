//! CRC checksums
//!
//! # Examples
//!
//! ```
//! use checksum_tapestry::crc::{BitWidth, CRCConfiguration, BitOrder, CRC};
//! use checksum_tapestry::Checksum;
//! let expected: u32 = 0xCBF43926;
//! let string = "123456789";
//! let data = string.as_bytes();
//! let mut crc32 = CRC::<u32>::new(CRCConfiguration::<u32>::new(
//!     "CRC-32/ISO-HDLC",
//!     BitWidth::ThirtyTwo,
//!     BitOrder::LSBFirst,
//!     0x04C11DB7,
//!     true,
//!     Some(0xFFFFFFFF),
//!     Some(0xFFFFFFFF),
//! ), true);
//!
//! let result: u32 = crc32.compute(&data);
//! assert_eq!(result, expected);
//! ```
#![warn(missing_docs)]
#![warn(unsafe_code)]

use core::default::Default;

use crate::{
    crc_table::{build_table_16, build_table_32, crc16, crc32},
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
    pub table: Option<[BITWIDTH; 256]>,

    /// state of the CRC for rolling checksums
    crc: BITWIDTH,
}

/// Configuration settings for CRC
/// This incorporates some advice from the parameter model described
/// in:
/// Williams, Ross N. "A Painless Guide to CRC Error Detection
/// Algorithms", Rocksoft Pty Ltd., 1993, crc_ross.pdf
///
/// It differs from that model in that a CRC bit order property is
/// used instead of relying solely on reflect in and reflect out.
/// BitOrder is used in the same way as reflect in, but uses
/// Rust-style enumerations.
#[derive(Clone, Copy)]
pub struct CRCConfiguration<'name, BITWIDTH: Width> {
    /// The common or standard name of this CRC32 configuration
    #[allow(dead_code)]
    name: &'name str,
    /// The bit-width
    pub width: BitWidth,

    /// The bit-order.
    ///
    /// This parameter is equivalent to setting reflect_in to true.
    ///
    /// Setting this to BitOrder::LSBFirst will cause the CRC
    /// calculations to behave as if reflect_in had been specified as
    /// true.
    ///
    /// Reflecting a binary value swaps the bits around the center, so
    /// 0b10110001 reflected would be 0b10001101 and
    /// 0b10001101 reflected would be 0b10110001
    ///
    /// Instead of reflecting the data as we process it, we can
    /// reflect the table we use for computation.
    pub bit_order: BitOrder,

    /// The polynomial represented as an unsigned integer
    pub poly: BITWIDTH,

    /// "Reflect" the final value
    /// If this setting is true and the bit order is MSBFirst, reflect
    /// the final value.  For most CRCs, if the bit order is MSBFirst,
    /// this is false and if the bit order is LSBFirst, this is true.
    reflect_out: bool,

    /// Initial value of the checksum
    initial: BITWIDTH,

    /// Whether the final value should be XORed before returned, and what it should
    /// be XORed with.
    xor_out: Option<BITWIDTH>,
}

impl<'name> CRCConfiguration<'name, u16> {
    /// Create a new CRC32Configuration
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'name str,
        width: BitWidth,
        bit_order: BitOrder,
        poly: u16,
        reflect_out: bool,
        initial: Option<u16>,
        xor_out: Option<u16>,
    ) -> CRCConfiguration<'name, u16> {
        // Default value for integer types is zero
        let initial = initial.unwrap_or_default();

        CRCConfiguration {
            name,
            width,
            bit_order,
            poly,
            reflect_out,
            initial,
            xor_out,
        }
    }
}

impl<'name> CRCConfiguration<'name, u32> {
    /// Create a new CRC32Configuration
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'name str,
        width: BitWidth,
        bit_order: BitOrder,
        poly: u32,
        reflect_out: bool,
        initial: Option<u32>,
        xor_out: Option<u32>,
    ) -> CRCConfiguration<'name, u32> {
        // Default value for integer types is zero
        let initial = initial.unwrap_or_default();

        CRCConfiguration {
            name,
            width,
            bit_order,
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

/// CRC32 bit order
///
/// This enumeration was previously called BitOrder.  It was
/// confusing and did not provide enough information to describe the
/// CRC configuration.
///
/// It has been renamed to BitOrder, and the variants are MSBFirst and
/// LSBFirstFirst.
///
/// The terms Most Significant Bit (MSB) and Least Significant Bit
/// (LSBFirst) (without First as a suffix / qualifier) are not usually used
/// to describe the order of bits in a byte or other data word.  They
/// are used to label which bit has the highest and lowest order place
/// in the byte or word.
///
/// Previously, these values were named simpy MSB and LSBFirst.  This was
/// confusing and wrong.  These have been renamed to
/// MostSignificantBitFirst and LeastSignificantBitFirst and the minor
/// version increased for the crate.  It's still < 1.0.0 so breaking
/// changes are acceptable.
///
/// MSBFirst means the Most Significant Bit occurs as the
#[derive(Clone, Copy)]
pub enum BitOrder {
    /// Most-significant bit first
    MSBFirst,
    /// Least-significant bit first
    LSBFirst,
}

impl<'a> CRC<'a, u32> {
    /// Create a new CRC
    /// If build_table is true, precompute a table to speed up multiple runs
    /// of the CRC.
    /// If build_table is false, don't build a table.
    /// This is useful on memory-constrained systems.
    ///
    /// # Examples
    /// ```
    /// use checksum_tapestry::crc::{BitWidth, CRCConfiguration, BitOrder, CRC};
    /// use checksum_tapestry::Checksum;
    /// let expected: u32 = 0xCBF43926;
    /// let string = "123456789";
    /// let data = string.as_bytes();
    /// let crc32 = CRC::<u32>::new(CRCConfiguration::<u32>::new(
    ///     "CRC-32/ISO-HDLC",
    ///     BitWidth::ThirtyTwo,
    ///     BitOrder::LSBFirst,
    ///     0x04C11DB7,
    ///     true,
    ///     Some(0xFFFFFFFF),
    ///     Some(0xFFFFFFFF),
    /// ), true);
    ///
    /// assert!(crc32.table.is_some());
    /// ```
    #[allow(dead_code)]
    pub fn new(configuration: CRCConfiguration<'a, u32>, build_table: bool) -> Self {
        let table = if build_table {
            Some(build_table_32(&configuration))
        } else {
            None
        };

        let crc = CRC::<u32>::init(&configuration);

        CRC {
            configuration,
            table,
            crc,
        }
    }

    /// Initiallize the CRC with the initial values
    pub fn init(configuration: &CRCConfiguration<'a, u32>) -> u32 {
        match configuration.bit_order {
            BitOrder::LSBFirst => {
                configuration.initial.reverse_bits() >> (32u8 - (configuration.width as u8))
            }
            BitOrder::MSBFirst => configuration.initial << (32u8 - (configuration.width as u8)),
        }
    }

    /// Get the current state of the CRC
    pub fn state(&self) -> u32 {
        self.crc
    }

    /// "Finalize" the CRC value
    /// For a rolling checksum, this calculates the final transforms,
    /// Such as reflecting the output and XORing the output
    pub fn finalize(&mut self) -> u32 {
        if let BitOrder::MSBFirst = self.configuration.bit_order {
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
}

impl<'a> CRC<'a, u16> {
    /// Create a new CRC
    /// If build_table is true, precompute a table to speed up multiple runs
    /// of the CRC.
    /// If build_table is false, don't build a table.
    /// This is useful on memory-constrained systems.
    ///
    /// # Examples
    /// ```
    /// use checksum_tapestry::crc::{BitWidth, CRCConfiguration, BitOrder, CRC};
    /// use checksum_tapestry::Checksum;
    /// let expected: u16 = 0x2189;
    /// let string = "123456789";
    /// let data = string.as_bytes();
    /// let crc = CRC::<u16>::new(
    ///     CRCConfiguration::<u16>::new(
    ///         "CRC-16/KERMIT",
    ///         BitWidth::Sixteen,
    ///         BitOrder::LSBFirst,
    ///         0x1021,
    ///         true,
    ///         None,
    ///         None,
    ///     ),
    ///     false,
    /// );
    /// assert!(crc.table.is_none());
    /// ```
    #[allow(dead_code)]
    pub fn new(configuration: CRCConfiguration<'a, u16>, build_table: bool) -> Self {
        // Work through how the CRC works, whether we need to incorporate
        // bit_order into both the table generation and the computation
        // BitOrder is related to the "reflection" parameter.
        let table = if build_table {
            Some(build_table_16(&configuration))
        } else {
            None
        };

        let crc = CRC::<u16>::init(&configuration);

        CRC {
            configuration,
            table,
            crc,
        }
    }

    /// Reset the CRC to the initial state
    /// Returns the CRC value
    fn init(configuration: &CRCConfiguration<'a, u16>) -> u16 {
        match configuration.bit_order {
            BitOrder::LSBFirst => {
                configuration.initial.reverse_bits() >> (16u8 - (configuration.width as u8))
            }
            BitOrder::MSBFirst => configuration.initial << (16u8 - (configuration.width as u8)),
        }
    }

    /// Get the current state of the CRC
    pub fn state(&self) -> u16 {
        self.crc
    }

    /// "Finalize" the CRC value
    /// For a rolling checksum, this calculates the final transforms,
    /// Such as reflecting the output and XORing the output
    pub fn finalize(&mut self) -> u16 {
        if let BitOrder::MSBFirst = self.configuration.bit_order {
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
}

impl<'a> Default for CRC<'a, u32> {
    fn default() -> Self {
        let poly: u32 = 0x04C11DB7;
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32",
            BitWidth::ThirtyTwo,
            BitOrder::MSBFirst,
            poly,
            false,
            None,
            None,
        );

        CRC::<u32>::new(configuration, true)
    }
}

impl<'a> Default for CRC<'a, u16> {
    fn default() -> Self {
        let poly: u16 = 0x1021;
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16",
            BitWidth::Sixteen,
            BitOrder::MSBFirst,
            poly,
            true,
            None,
            None,
        );

        CRC::<u16>::new(configuration, true)
    }
}

impl<'a> Checksum<u32> for CRC<'a, u32> {
    fn compute(&mut self, data: &[u8]) -> u32 {
        self.crc = CRC::<u32>::init(&self.configuration);

        for byte in data {
            self.update(*byte);
        }

        self.finalize()
    }

    fn update(&mut self, data: u8) -> u32 {
        // table is an array of 256 32-bit constants
        self.crc = match self.configuration.bit_order {
            BitOrder::LSBFirst => {
                let index: u32 = (self.crc ^ (data as u32)) & 0xFF;
                let val = if let Some(table) = self.table {
                    table[index as usize]
                } else {
                    crc32(&self.configuration, index)
                };
                (self.crc >> 8) ^ val
            }
            BitOrder::MSBFirst => {
                let index: u32 = ((self.crc >> 24) ^ (data as u32)) & 0xFF;
                let val = if let Some(table) = self.table {
                    table[index as usize]
                } else {
                    crc32(&self.configuration, index)
                };
                (self.crc << 8) ^ val
            }
        };

        self.crc
    }

    /// Reset the CRC to the initial state
    /// Returns the CRC value
    fn reset(&mut self) {
        self.crc = CRC::<u32>::init(&self.configuration);
    }
}

impl<'a> Checksum<u16> for CRC<'a, u16> {
    fn compute(&mut self, data: &[u8]) -> u16 {
        self.crc = CRC::<u16>::init(&self.configuration);

        for byte in data {
            self.update(*byte);
        }

        self.finalize()
    }

    // TODO: Optimize for table vs. non-table versions.  Instead of
    // checking every update, have ::new create a version without a
    // check.
    fn update(&mut self, data: u8) -> u16 {
        // table is an array of 256 16-bit constants

        self.crc = match self.configuration.bit_order {
            BitOrder::LSBFirst => {
                let index = (self.crc ^ (data as u16)) & 0xFF;
                let val = if let Some(table) = self.table {
                    table[index as usize]
                } else {
                    crc16(&self.configuration, index)
                };
                (self.crc >> 8) ^ val
            }
            BitOrder::MSBFirst => {
                let index = ((self.crc >> 8) ^ (data as u16)) & 0xFF;
                let val = if let Some(table) = self.table {
                    table[index as usize]
                } else {
                    crc16(&self.configuration, index)
                };
                (self.crc << 8) ^ val
            }
        };

        self.crc
    }

    /// Reset the CRC to the initial state
    /// Returns the CRC value
    /// It's not very RAII
    /// TODO: Fix this up
    fn reset(&mut self) {
        self.crc = CRC::<u16>::init(&self.configuration);
    }
}

#[cfg(test)]
mod tests {
    use super::{BitOrder, BitWidth, CRCConfiguration, CRC};
    use crate::Checksum;

    /// Test CRC-3-GSM MSBFirst
    #[test]
    fn crc_3_gsm_works() {
        let string = "123456789";
        let data = string.as_bytes();
        let mut crc3 = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-3/GSM",
                BitWidth::Three,
                BitOrder::MSBFirst,
                0b011,
                false,
                None,
                Some(0b111),
            ),
            true,
        );
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
        let mut crc32 = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/ISO-HDLC",
                BitWidth::ThirtyTwo,
                BitOrder::LSBFirst,
                0x04C11DB7,
                true,
                Some(0xFFFFFFFF),
                Some(0xFFFFFFFF),
            ),
            true,
        );

        let result: u32 = crc32.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-16/Genibus
    #[test]
    fn crc_16_genibus_works() {
        let expected: u16 = 0xD64E;
        let string = "123456789";
        let data = string.as_bytes();
        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-32/Genibus",
                BitWidth::Sixteen,
                BitOrder::MSBFirst,
                0x1021,
                false,
                Some(0xFFFF),
                Some(0xFFFF),
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-12/UMTS
    #[test]
    fn crc_16_umts_works() {
        let expected: u16 = 0xDAF;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-12/UMTS",
                BitWidth::Twelve,
                BitOrder::MSBFirst,
                0x80F,
                true,
                None,
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/BZIP2
    #[test]
    fn crc_32_bzip2_works() {
        let expected: u32 = 0xFC891918;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/BZIP2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                Some(0xFFFFFFFF),
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/MPEG-2
    #[test]
    fn crc_32_mpeg2_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/MPEG-2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-16/KERMIT
    #[test]
    fn crc_16_kermit_works() {
        let expected: u16 = 0x2189;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-16/KERMIT",
                BitWidth::Sixteen,
                BitOrder::LSBFirst,
                0x1021,
                true,
                None,
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test CRC-32/iSCSI, also called CRC-32C (Castagnoli)
    #[test]
    fn crc_32_iscsi_works() {
        let expected: u32 = 0xE3069283;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/iSCSI",
                BitWidth::ThirtyTwo,
                BitOrder::LSBFirst,
                0x1EDC6F41,
                true,
                Some(0xFFFFFFFF),
                Some(0xFFFFFFFF),
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test calling compute twice works
    #[test]
    fn compute_called_twice_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/MPEG-2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test calling reset with a default constructor works for a CRC-32
    #[test]
    fn reset_crc_32_with_default_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/MPEG-2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);

        crc.reset();
        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test reset for with a default constructor works for a CRC-16
    #[test]
    fn reset_crc_16_with_default_works() {
        let expected: u16 = 0x2189;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-16/KERMIT",
                BitWidth::Sixteen,
                BitOrder::LSBFirst,
                0x1021,
                true,
                None,
                None,
            ),
            true,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);

        crc.reset();
        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test calling reset with a default constructor works for a CRC-32
    /// Use case of rolling update
    #[test]
    fn reset_crc_32_with_default_update_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/MPEG-2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                None,
            ),
            true,
        );

        let mut result: u32;
        for byte in data {
            crc.update(*byte);
        }
        result = crc.finalize();
        assert_eq!(result, expected);

        crc.reset();
        for byte in data {
            crc.update(*byte);
        }
        result = crc.finalize();
        assert_eq!(result, expected);
    }

    /// Test reset for with a default constructor works for a CRC-16
    /// Use case of rolling update
    #[test]
    fn reset_crc_16_with_default_update_works() {
        let expected: u16 = 0x2189;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-16/KERMIT",
                BitWidth::Sixteen,
                BitOrder::LSBFirst,
                0x1021,
                true,
                None,
                None,
            ),
            true,
        );

        let mut result: u16;
        for byte in data {
            crc.update(*byte);
        }
        result = crc.finalize();
        assert_eq!(result, expected);

        crc.reset();
        for byte in data {
            crc.update(*byte);
        }
        result = crc.finalize();
        assert_eq!(result, expected);
    }

    /// Test building a CRC without table optimizations
    /// Test CRC-32/MPEG-2
    #[test]
    fn crc_32_mpeg2_no_table_works() {
        let expected: u32 = 0x0376E6E7;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u32>::new(
            CRCConfiguration::<u32>::new(
                "CRC-32/MPEG-2",
                BitWidth::ThirtyTwo,
                BitOrder::MSBFirst,
                0x04C11DB7,
                false,
                Some(0xFFFFFFFF),
                None,
            ),
            false,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }

    /// Test building a CRC without table optimizations
    /// Test CRC-16/KERMIT
    #[test]
    fn crc_16_kermit_no_table_works() {
        let expected: u16 = 0x2189;
        let string = "123456789";
        let data = string.as_bytes();

        let mut crc = CRC::<u16>::new(
            CRCConfiguration::<u16>::new(
                "CRC-16/KERMIT",
                BitWidth::Sixteen,
                BitOrder::LSBFirst,
                0x1021,
                true,
                None,
                None,
            ),
            false,
        );

        let result = crc.compute(&data);
        assert_eq!(result, expected);
    }
}
