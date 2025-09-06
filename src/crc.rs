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

use core::fmt::{Debug, Display, Error, Formatter};

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

impl<'a> Debug for CRC<'a, u16> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "configuration: {:?}", self.configuration)?;
        writeln!(f, ", crc: 0x{:04X}", self.crc)?;

        if let Some(table) = self.table {
            writeln!(f, "table:")?;
            for (i, &byte) in table.iter().enumerate() {
                write!(f, "0x{:04X}, ", byte)?;
                if ((i + 1) % 8) == 0 {
                    writeln!(f)?;
                }
            }
            writeln!(f)
        } else {
            write!(f, "")
        }
    }
}

impl<'a> Debug for CRC<'a, u32> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "configuration: {:?}", self.configuration)?;
        writeln!(f, ", crc: 0x{:08X}", self.crc)?;

        if let Some(table) = self.table {
            writeln!(f, "table:")?;
            for (i, &byte) in table.iter().enumerate() {
                write!(f, "0x{:08X}, ", byte)?;
                if ((i + 1) % 8) == 0 {
                    writeln!(f)?;
                }
            }
            writeln!(f)
        } else {
            write!(f, "")
        }
    }
}

/// How the polynomial is encoded as binary in the CRCConfiguration
///
/// This addition duplicates some information in the CRCConfiguration,
/// but it also more explicitly defines how polynomials are encoded or
/// represented.
///
/// For the following documentation, the "CRC-4/ITU" polynomial is
/// used.  This is a 4-bit polynomial: x^4 + x + 1
///
/// Previously, if the CRCConfiguration bit_order was MSBFirst, then
/// the polynomial was assumed to be encoded as MSBFirst.  What was
/// left unsaid was that the most-significant coefficient in the
/// polynomial was not included in the binary representation.
/// For a 4-bit polynomial x^4 + x + 1 it would be: 0b11
///
/// If the CRCConfiguration was LSBFirst, then the polynomial was
/// encoded as LSBFirst, and again the high-order bit IS NOT included.
/// For a 4-bit polynomial x^4 + x + 1, it would be encoding 1 + x +
/// x^4 as 0b1100
///
/// This new enumeration and associated Polynomial type that uses it
/// includes that information explicitly as part of the specification.
/// In addition there is a new type of representation, Koopman, that
/// includes the high-order bit but not the low-order bit.
#[derive(Debug)]
pub enum PolynomialEncoding {
    /// MSBFirst Encoding
    ///
    /// The polynomial is encoded with the most-significant bit (MSB)
    /// first.  In addition the high-order bit IS NOT included.
    ///
    /// For example, for the 4-bit polynomial x^4 + x + 1:
    /// x^4 + x + 1 = 1x^4 + 0x^3 + 0x^2 + 1x^1 + 1x^0 =>
    /// 0b00011 = 0b11 = 0x3
    MSBFirst,

    /// LSBFirst Encoding
    ///
    /// The polynomial is encoded with the least-significant bit (LSB)
    /// first.  In addition the high-order bit IS NOT included.
    ///
    /// For example, for the 4-bit polynomial x^4 + x + 1:
    /// x^4 + x + 1 = 1x^4 + 0x^3 + 0x^2 + 1x^1 + 1x^0 =>
    /// 1x^0 + 1x^1 + 0x^2 + 0x^3 + 1x^4 =>
    /// 0b01100 = 0b1100 = 0xc
    LSBFirst,

    /// Koopman Encoding
    ///
    /// The polynomial is encoded with the most-significant bit first.
    /// The high-order bit IS included in the encoding, but the
    /// low-order bit IS NOT.
    ///
    /// For example, for the 4-bit polynomial x^4 + x + 1:
    /// x^4 + x + 1 = 1x^4 + 0x^3 + 0x^2 + 1x^1 + 1x^0 =>
    /// 0b1001 =  0x09
    Koopman,
}

/// This is a CRC polynomial that includes explicit information about
/// how the polynomial is encoded.
pub struct Polynomial<BITWIDTH: Width> {
    /// The encoding of the polynomial
    pub encoding: PolynomialEncoding,
    /// The bit-width of the polynomial.
    ///
    /// This is REQUIRED since some polynomials may have the same
    /// encoding but what that encoding means differs based on the
    /// bitwidth.  For example:
    ///
    /// CRC-3/GSM (a polynomial with a width of 3) x^3 + x + 1
    /// and CRC-4/ITU (a polynomial with a width of 4): x^4 + x + 1
    /// are both commonly encoded as: 0b11 (0x3)
    pub width: BitWidth,
    /// The polynonomial encoded as a BITWIDTH bit unsigned integer
    pub polynomial: BITWIDTH,
}

// Implementations for u16 polynomials

impl Polynomial<u16> {
    /// Return a binary representation of the actual polynomial
    ///
    /// This isn't the encoded form with missing first or last terms.
    /// This is the full generator polynomial for the CRC.
    ///
    /// # Arguments
    ///
    /// * `&self` - A reference to the Polynomial structure
    ///
    /// # Returns
    ///
    /// The polynomial encoded as a 32-bit bitvector with the smallest
    /// term (x^0) as the least-significant bit.
    pub fn actual_polynomial(&self) -> u32 {
        let w: u16 = (self.width as u8).into();

        let mut poly: u32 = 0;

        match self.encoding {
            PolynomialEncoding::MSBFirst => {
                poly = 2_u32.pow((w).into()) | self.polynomial as u32;
            }
            PolynomialEncoding::LSBFirst => {
                let mut tmp_poly = self.polynomial;
                for i in (0..w).rev() {
                    if (tmp_poly & 1) == 1 {
                        poly |= 2_u32.pow(i.into());
                    }
                    tmp_poly >>= 1;
                }
                poly |= 1;
                poly |= 2_u32.pow((w).into());
            }
            PolynomialEncoding::Koopman => {
                poly = ((self.polynomial as u32) << 1) | 1;
            }
        }

        poly
    }

    /// Write the Polynomial to a formatter
    ///
    /// # Arguments
    ///
    /// * `&self` - A reference to the Polynomial structure
    /// * `f` - The Formatter to write to
    /// * `actual_polynomial`: A 32-bit bitvector representing the
    ///   polynomial's coefficients
    ///
    /// # Returns
    ///
    /// A Result with the unit on success and a core::fmt::Error on
    /// errors
    fn write(&self, f: &mut Formatter<'_>, actual_polynomial: u32) -> Result<(), core::fmt::Error> {
        let w = self.width as u8;

        for i in 0..=w {
            let term = w - i;
            if ((actual_polynomial >> term) & 1) == 1 {
                if i != 0 {
                    write!(f, " + ")?;
                }
                if i == w {
                    write!(f, "1")?;
                } else if i == (w - 1) {
                    write!(f, "x")?;
                } else {
                    write!(f, "x^{}", term)?;
                }
            }
        }

        write!(f, "")
    }
}

impl Debug for Polynomial<u16> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "encoding: {:?}, ", self.encoding)?;
        write!(f, "width: {:?}, ", self.width)?;

        let poly: u32 = self.actual_polynomial();

        write!(f, "polynomial: ")?;
        self.write(f, poly)
    }
}

impl Display for Polynomial<u16> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let poly: u32 = self.actual_polynomial();
        self.write(f, poly)
    }
}

// Implementations for u32 polynomials

impl Polynomial<u32> {
    /// Return a binary representation of the actual polynomial
    ///
    /// This isn't the encoded form with missing first or last terms.
    /// This is the full generator polynomial for the CRC.
    ///
    /// # Arguments
    ///
    /// * `&self` - A reference to the Polynomial structure
    ///
    /// # Returns
    ///
    /// The polynomial encoded as a 64-bit bitvector with the smallest
    /// term (x^0) as the least-significant bit.
    pub fn actual_polynomial(&self) -> u64 {
        let w: u32 = (self.width as u8).into();

        let mut poly: u64 = 0;

        match self.encoding {
            PolynomialEncoding::MSBFirst => {
                poly = 2_u64.pow(w) | self.polynomial as u64;
            }
            PolynomialEncoding::LSBFirst => {
                let mut tmp_poly = self.polynomial;
                for i in (0..w).rev() {
                    if (tmp_poly & 1) == 1 {
                        poly |= 2_u64.pow(i);
                    }
                    tmp_poly >>= 1;
                }
                poly |= 1;
                poly |= 2_u64.pow(w);
            }
            PolynomialEncoding::Koopman => {
                poly = ((self.polynomial as u64) << 1) | 1;
            }
        }

        poly
    }

    /// Write the Polynomial to a formatter
    ///
    /// # Arguments
    ///
    /// * `&self` - A reference to the Polynomial structure
    /// * `f` - The Formatter to write to
    /// * `actual_polynomial`: A 64-bit bitvector representing the
    ///   polynomial's coefficients
    ///
    /// # Returns
    ///
    /// A Result with the unit on success and a core::fmt::Error on
    /// errors
    fn write(&self, f: &mut Formatter<'_>, actual_polynomial: u64) -> Result<(), core::fmt::Error> {
        let w = self.width as u8;

        for i in 0..=w {
            let term = w - i;
            if ((actual_polynomial >> term) & 1) == 1 {
                if i != 0 {
                    write!(f, " + ")?;
                }
                if i == w {
                    write!(f, "1")?;
                } else if i == (w - 1) {
                    write!(f, "x")?;
                } else {
                    write!(f, "x^{}", term)?;
                }
            }
        }

        write!(f, "")
    }
}

impl Debug for Polynomial<u32> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "encoding: {:?}, ", self.encoding)?;
        write!(f, "width: {:?}, ", self.width)?;

        let poly: u64 = self.actual_polynomial();

        write!(f, "polynomial: ")?;
        self.write(f, poly)
    }
}

impl Display for Polynomial<u32> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        let poly: u64 = self.actual_polynomial();
        self.write(f, poly)
    }
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

impl<'name> Debug for CRCConfiguration<'name, u16> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "name: {:?}", self.name)?;
        write!(f, ", width: {:?}", self.width)?;
        write!(f, ", bit_order: {:?}", self.bit_order)?;
        write!(f, ", polynomial: 0x{:04X}", self.poly)?;
        write!(f, ", reflect_out: {:?}", self.reflect_out)?;

        write!(f, ", initial: 0x{:04X}", self.initial)?;
        if let Some(xor_out) = self.xor_out {
            write!(f, ", xor_out: 0x{:04X}", xor_out)
        } else {
            write!(f, ", xor_out: None")
        }
    }
}

impl<'name> Debug for CRCConfiguration<'name, u32> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "name: {:?}", self.name)?;
        write!(f, ", width: {:?}", self.width)?;
        write!(f, ", bit_order: {:?}", self.bit_order)?;
        write!(f, ", polynomial: 0x{:08X}", self.poly)?;
        write!(f, ", reflect_out: {:?}", self.reflect_out)?;

        write!(f, ", initial: 0x{:08X}", self.initial)?;
        if let Some(xor_out) = self.xor_out {
            write!(f, ", xor_out: 0x{:08X}", xor_out)
        } else {
            write!(f, ", xor_out: None")
        }
    }
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
#[derive(Clone, Copy, Debug)]
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
/// LSBFirst.
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
#[derive(Clone, Copy, Debug)]
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
    use super::{BitOrder, BitWidth, CRCConfiguration, Polynomial, PolynomialEncoding, CRC};
    use crate::Checksum;

    // Here we have a Wrapper struct and implmentation of Write for
    // the Wrapper so we can write into byte buffers without an allocator
    //
    // This code is from Stack Overflow by [shepmaster](https://stackoverflow.com/users/155423/shepmaster)
    // [https://stackoverflow.com/questions/39488327/how-to-format-output-to-a-byte-array-with-no-std-and-no-allocator](How to format output to a byte array with no_std and no allocator?)
    use core::fmt::{self, Write};

    /// A Wrapper struct that stores a byte slice and offset that
    /// points to the next valid write location.
    struct Wrapper<'a> {
        /// Reference to a mutable byte slice for writing to
        buf: &'a mut [u8],
        /// Byte offset into the current valid location for writing
        offset: usize,
    }

    impl<'a> Wrapper<'a> {
        /// Create a new Wrapper with buf as the backing byte buffer.
        fn new(buf: &'a mut [u8]) -> Self {
            Wrapper { buf, offset: 0 }
        }
    }

    impl<'a> fmt::Write for Wrapper<'a> {
        /// Write a string slice into a Wrapper
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();

            // Skip over already-copied data
            let remainder = &mut self.buf[self.offset..];
            // Check if there is space remaining (return error instead of panicking)
            if remainder.len() < bytes.len() {
                return Err(core::fmt::Error);
            }
            // Make the two slices the same length
            let remainder = &mut remainder[..bytes.len()];
            // Copy
            remainder.copy_from_slice(bytes);

            // Update offset to avoid overwriting
            self.offset += bytes.len();

            Ok(())
        }
    }

    // Test Polynomial Display and Debug traits

    /// Test CRC-3/GSM PolynomialEncoding::MSBFirst debug trait works
    #[test]
    fn polynomial_crc_3_gsm_polynomial_encoding_msbfirst_debug_works() {
        let poly = Polynomial::<u16> {
            encoding: PolynomialEncoding::MSBFirst,
            width: BitWidth::Three,
            polynomial: 0x3,
        };

        let expected = "encoding: MSBFirst, width: Three, polynomial: x^3 + x + 1";
        let mut buf: [u8; 128] = [0; 128];
        write!(Wrapper::new(&mut buf), "{:?}", poly).expect("Can't write Polynomial");

        // Unicode allows NULL bytes in strings
        // But we want to remove them here.
        //
        // There is a good likelihood this crate gets localization in
        // the future, so we want to support UTF-8 or some UTF
        // encoding.  e.g. polynôme and codificación both include
        // non-ASCII characters
        //
        // So we'll do trim_matches as a compromise instead of
        // pulling in more crates
        let buf_str = core::str::from_utf8(buf.as_slice())
            .expect("Should be able to convert to str")
            .trim_matches(char::from(0));
        assert_eq!(buf_str, expected);
    }

    /// Test CRC-3/GSM PolynomialEncoding::LSBFirst debug trait works
    #[test]
    fn polynomial_crc_3_gsm_polynomial_encoding_lsbfirst_debug_works() {
        let poly = Polynomial::<u16> {
            encoding: PolynomialEncoding::LSBFirst,
            width: BitWidth::Three,
            polynomial: 0x6,
        };

        let expected = "encoding: LSBFirst, width: Three, polynomial: x^3 + x + 1";
        let mut buf: [u8; 128] = [0; 128];
        write!(Wrapper::new(&mut buf), "{:?}", poly).expect("Can't write Polynomial");

        let buf_str = core::str::from_utf8(buf.as_slice())
            .expect("Should be able to convert to str")
            .trim_matches(char::from(0));
        assert_eq!(buf_str, expected);
    }

    /// Test CRC-3/GSM PolynomialEncoding::Koopman debug trait works
    #[test]
    fn polynomial_crc_3_gsm_polynomial_encoding_koopman_debug_works() {
        let poly = Polynomial::<u16> {
            encoding: PolynomialEncoding::Koopman,
            width: BitWidth::Three,
            polynomial: 0x5,
        };

        let expected = "encoding: Koopman, width: Three, polynomial: x^3 + x + 1";
        let mut buf: [u8; 128] = [0; 128];
        write!(Wrapper::new(&mut buf), "{:?}", poly).expect("Can't write Polynomial");

        let buf_str = core::str::from_utf8(buf.as_slice())
            .expect("Should be able to convert to str")
            .trim_matches(char::from(0));
        assert_eq!(buf_str, expected);
    }

    /// Test displaying a 32-bit Polynomial
    ///
    /// This is a good test because the Polynomial encoding is
    /// PolynomialEncoding::MSBFirst, but the CRCConfiguration for the
    /// standard "CRC-32/ISO-HDLC" is "BitOrder::LSBFirst" in my
    /// configuration language.
    ///
    /// Using the language of Ross Williams' the parameters for the
    /// CRCConfiguration are: reflect_in is true, reflect_out is true,
    /// initial is 0xffffffff, final XOR is 0xffffffff
    #[test]
    fn polynomial_crc_32_iso_hdlc_polynomial_encoding_msbfirst_debug_works() {
        let _ = env_logger::try_init();
        let poly = Polynomial::<u32> {
            encoding: PolynomialEncoding::MSBFirst,
            width: BitWidth::ThirtyTwo,
            polynomial: 0x04C11DB7,
        };

        let expected = "encoding: MSBFirst, width: ThirtyTwo, polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1";
        let mut buf: [u8; 256] = [0; 256];
        write!(Wrapper::new(&mut buf), "{:?}", poly).expect("Can't write Polynomial");

        let buf_str = core::str::from_utf8(buf.as_slice())
            .expect("Should be able to convert to str")
            .trim_matches(char::from(0));
        assert_eq!(buf_str, expected);
    }

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

        let result = crc3.compute(data);
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

        let result: u32 = crc32.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
        assert_eq!(result, expected);

        let result = crc.compute(data);
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

        let result = crc.compute(data);
        assert_eq!(result, expected);

        crc.reset();
        let result = crc.compute(data);
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

        let result = crc.compute(data);
        assert_eq!(result, expected);

        crc.reset();
        let result = crc.compute(data);
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

        let result = crc.compute(data);
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

        let result = crc.compute(data);
        assert_eq!(result, expected);
    }
}
