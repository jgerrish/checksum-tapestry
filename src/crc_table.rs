//! CRC table generation code.
//! These are different versions of CRC table generation code.
//! This includes optimized and unoptimized versions.
//! CRC generation code was based on the crc crate
use crate::crc::{CRCConfiguration, CRCEndianness};

/// Compute a CRC using a 16-bit polynomial
///
/// # Examples
///
///
/// ```
/// use checksum_tapestry::{
///     Checksum,
///     crc::{BitWidth, CRCConfiguration, CRCEndianness},
///     crc_table::crc16,
/// };
///
/// let configuration = CRCConfiguration::<u16>::new(
///     "CRC-16/CCITT",
///     BitWidth::Sixteen,
///     CRCEndianness::MSB,
///     0x1021,
///     true,
///     None,
///     None,
/// );
///
/// let crc = crc16(&configuration, 0xBBCE as u16);
/// assert_eq!(crc, 0x3882);
/// ```
///
pub const fn crc16(configuration: &CRCConfiguration<u16>, mut value: u16) -> u16 {
    let poly = match configuration.endianness {
        CRCEndianness::MSB => configuration.poly << (16 - (configuration.width as u8)),
        CRCEndianness::LSB => {
            let poly = configuration.poly.reverse_bits();
            poly >> (16 - (configuration.width as u8))
        }
    };

    if let CRCEndianness::LSB = configuration.endianness {
        let mut i = 0;
        while i < 8 {
            value = (value >> 1) ^ ((value & 1) * poly);
            i += 1;
        }
    } else {
        value <<= 8;

        let mut i = 0;
        while i < 8 {
            value = (value << 1) ^ (((value >> 15) & 1) * poly);
            i += 1;
        }
    }
    value
}

/// Compute a CRC using a 32-bit polynomial
///
/// # Examples
///
///
/// ```
/// use checksum_tapestry::{
///     Checksum,
///     crc::{BitWidth, CRCConfiguration, CRCEndianness},
///     crc_table::crc32,
/// };
///
/// let configuration = CRCConfiguration::<u32>::new(
///     "CRC-32/MPEG-2",
///     BitWidth::ThirtyTwo,
///     CRCEndianness::MSB,
///     0x04C11DB7,
///     false,
///     Some(0xFFFFFFFF),
///     None,
/// );
///
/// let crc = crc32(&configuration, 0x00BBCE7B as u32);
/// assert_eq!(crc, 0xCBFFD686);
/// ```
///
pub const fn crc32(configuration: &CRCConfiguration<u32>, mut value: u32) -> u32 {
    let poly = match configuration.endianness {
        CRCEndianness::MSB => configuration.poly << (32 - (configuration.width as u8)),
        CRCEndianness::LSB => {
            let poly = configuration.poly.reverse_bits();
            poly >> (32 - (configuration.width as u8))
        }
    };

    if let CRCEndianness::LSB = configuration.endianness {
        let mut i = 0;
        while i < 8 {
            value = (value >> 1) ^ ((value & 1) * poly);
            i += 1;
        }
    } else {
        value <<= 24;

        let mut i = 0;
        while i < 8 {
            value = (value << 1) ^ (((value >> 31) & 1) * poly);
            i += 1;
        }
    }
    value
}

/// This builds the CRC based on the endianness, as opposed to the reflect_in
/// and reflect_out parameters.
/// It supports most use-cases, but there are some CRCs, like CRC-16/Genibus
/// that require unmatched reflect_in and reflect_out settings.
/// The real-world is messy.
/// These are simpler to understand than optimized table generation
/// routines that make use of the fact that table[i xor j] == table[i]
/// xor table[j], so that we only have to update entries corresponding
/// to powers of two.
///
/// This is based on the Sarwate method, outlined in Sarwate, Dilip
/// V. (August 1998). "Computation of Cyclic Redundancy Checks via
/// Table Look-Up". Communications of the ACM. 31 (8):
/// 1008–1013. doi:10.1145/63030.63037. S2CID 5363350.
///
/// The tutorial at
/// https://github.com/komrad36/CRC/blob/master/README.md by komrad36
/// provides a very good overview of why this works.
///
/// # Examples
///
/// ```
/// use checksum_tapestry::{
///     Checksum,
///     crc::{BitWidth, CRCConfiguration, CRCEndianness},
///     crc_table::build_table_16,
/// };
///
/// let configuration = CRCConfiguration::<u16>::new(
///     "CRC-16/KERMIT",
///     BitWidth::Sixteen,
///     CRCEndianness::LSB,
///     0x1021,
///     // true,
///     true,
///     None,
///     None,
/// );
///
/// let table = build_table_16(&configuration);
/// ```
pub fn build_table_16(configuration: &CRCConfiguration<u16>) -> [u16; 256] {
    let mut table: [u16; 256] = [0; 256];
    let mut i = 0;

    while i < table.len() {
        table[i] = crc16(configuration, i as u16);
        i += 1;
    }
    table
}

/// This builds the CRC based on the endianness, as opposed to the reflect_in
/// and reflect_out parameters.
/// It supports most use-cases, but there are some CRCs, like CRC-16/Genibus
/// that require unmatched reflect_in and reflect_out settings.
/// The real-world is messy.
/// These are simpler to understand than optimized table generation
/// routines that make use of the fact that table[i xor j] == table[i]
/// xor table[j], so that we only have to update entries corresponding
/// to powers of two.
///
/// This is based on the Sarwate method, outlined in Sarwate, Dilip
/// V. (August 1998). "Computation of Cyclic Redundancy Checks via
/// Table Look-Up". Communications of the ACM. 31 (8):
/// 1008–1013. doi:10.1145/63030.63037. S2CID 5363350.
///
/// The tutorial at
/// https://github.com/komrad36/CRC/blob/master/README.md by komrad36
/// provides a very good overview of why this works.
///
/// # Examples
///
/// ```
/// use checksum_tapestry::{
///     Checksum,
///     crc::{BitWidth, CRCConfiguration, CRCEndianness},
///     crc_table::build_table_32,
/// };
///
/// let mut configuration = CRCConfiguration::<u32>::new(
///     "CRC-32/MPEG-2",
///     BitWidth::ThirtyTwo,
///     CRCEndianness::MSB,
///     0x04C11DB7,
///     false,
///     Some(0xFFFFFFFF),
///     None,
/// );
///
/// let table = build_table_32(&configuration);
/// ```
pub fn build_table_32(configuration: &CRCConfiguration<u32>) -> [u32; 256] {
    let mut table: [u32; 256] = [0; 256];
    let mut i = 0;

    while i < table.len() {
        table[i] = crc32(configuration, i as u32);
        i += 1;
    }
    table
}

/// Build a CRC table for MSB 32-bit CRCs
///
/// Make use of the fact that table[i xor j] == table[i] xor table[j],
/// we only have to update entries corresponding to powers of two
pub fn optimized_build_msb_table_32(configuration: &CRCConfiguration<u32>) -> [u32; 256] {
    let mut table: [u32; 256] = [0; 256];
    let mut crc: u32;

    let mut i = 1;

    // i starts at 1 and is shifted left every iteration, so values of i are:
    // 1, 2, 4, 8, 16, 32, 64, 128
    while i < 256 {
        crc = crc32(configuration, i as u32);

        // j iterates from 0 to i - 1, or 0 to 0, non-inclusive
        // So on the first outer iteration, it iterates from 0 to 0,
        // It doesn't enter the loop.
        // On the next iteration it iterates from 0 to 1, non-inclusive,
        // It enters the loop once.
        for j in 0..i {
            table[i ^ j] = crc ^ table[j];
        }
        i <<= 1;
    }

    table
}

/// Build a CRC table for LSB 32-bit CRCs
///
/// Make use of the fact that table[i xor j] == table[i] xor table[j],
/// we only have to update entries corresponding to powers of two
pub fn optimized_build_lsb_table_32(configuration: &CRCConfiguration<u32>) -> [u32; 256] {
    let mut table: [u32; 256] = [0; 256];
    let mut crc: u32;
    let mut i: usize = 128;

    while i > 0 {
        crc = crc32(configuration, i as u32);

        let mut j = 0;
        while j < 256 {
            table[i ^ j] = crc ^ table[j];
            j += 2 * i;
        }
        i >>= 1;
    }

    table
}

/// Build a CRC table for MSB 16-bit CRCs
///
/// Make use of the fact that table[i xor j] == table[i] xor table[j],
/// we only have to update entries corresponding to powers of two
pub fn optimized_build_msb_table_16(configuration: &CRCConfiguration<u16>) -> [u16; 256] {
    let mut table: [u16; 256] = [0; 256];
    let mut crc;

    let mut i = 1;

    while i < 256 {
        crc = crc16(configuration, i as u16);

        for j in 0..i {
            table[i ^ j] = crc ^ table[j];
        }
        i <<= 1;
    }

    table
}

/// Build a CRC table for LSB 16-bit CRCs
///
/// Make use of the fact that table[i xor j] == table[i] xor table[j],
/// we only have to update entries corresponding to powers of two
pub fn optimized_build_lsb_table_16(configuration: &CRCConfiguration<u16>) -> [u16; 256] {
    let mut table: [u16; 256] = [0; 256];
    let mut crc: u16;
    let mut i: usize = 128;

    while i > 0 {
        crc = crc16(configuration, i as u16);

        let mut j = 0;
        while j < 256 {
            table[i ^ j] = crc ^ table[j];
            j += 2 * i;
        }
        i >>= 1;
    }

    table
}

#[cfg(test)]
mod tests {
    use crate::crc::{BitWidth, CRCConfiguration, CRCEndianness};

    use super::{
        build_table_16, build_table_32, optimized_build_lsb_table_16, optimized_build_lsb_table_32,
        optimized_build_msb_table_16, optimized_build_msb_table_32,
    };

    /// This contains a table generated from the CCITT 16-bit polynomial.
    /// Used to test the table generation code.
    /// Below is the configuration.
    /// let configuration = CRCConfiguration::<u16>::new(
    ///     "CRC-16/CCITT",
    ///     BitWidth::Sixteen,
    ///     CRCEndianness::MSB,
    ///     0x1021,
    ///     true,
    ///     None,
    ///     None,
    /// );
    const CCITT_TABLE: [u16; 256] = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A,
        0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294,
        0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462,
        0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509,
        0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695,
        0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 0x48C4, 0x58E5,
        0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948,
        0x9969, 0xA90A, 0xB92B, 0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
        0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4,
        0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B,
        0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F,
        0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78, 0x9188, 0x81A9, 0xB1CA, 0xA1EB,
        0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046,
        0x6067, 0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290,
        0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256, 0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E,
        0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691,
        0x16B0, 0x6657, 0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9,
        0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3, 0xCB7D,
        0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16,
        0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8,
        0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E,
        0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93,
        0x3EB2, 0x0ED1, 0x1EF0,
    ];

    /// This contains a table generated from the KERMIT 16-bit polynomial.
    /// Used to test the table generation code.
    /// Below is the configuration.
    /// let configuration = CRCConfiguration::<u16>::new(
    ///     "CRC-16/KERMIT",
    ///     BitWidth::Sixteen,
    ///     CRCEndianness::LSB,
    ///     0x1021,
    ///     true,
    ///     true,
    ///     None,
    ///     None,
    /// );
    const KERMIT_TABLE: [u16; 256] = [
        0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A,
        0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C,
        0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876, 0x2102,
        0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1,
        0xEB6E, 0xFAE7, 0xC87C, 0xD9F5, 0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5,
        0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974, 0x4204, 0x538D,
        0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868,
        0x99E1, 0xAB7A, 0xBAF3, 0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
        0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72, 0x6306, 0x728F, 0x4014,
        0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3,
        0x8A78, 0x9BF1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738, 0xFFCF,
        0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70, 0x8408, 0x9581, 0xA71A, 0xB693,
        0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76,
        0x7CFF, 0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1, 0x0948,
        0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E, 0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E,
        0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
        0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1,
        0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1,
        0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB, 0xD68D,
        0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232, 0x5AC5, 0x4B4C, 0x79D7, 0x685E,
        0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, 0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238,
        0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9, 0xF78F, 0xE606,
        0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3,
        0x2C6A, 0x1EF1, 0x0F78,
    ];

    /// This contains a table generated from the MPEG2 32-bit polynomial
    /// Used to test the table generation code.
    /// Below is the configuration:
    /// let configuration = CRCConfiguration::<u32>::new(
    ///     "CRC-32/MPEG-2",
    ///     BitWidth::ThirtyTwo,
    ///     CRCEndianness::MSB,
    ///     0x04C11DB7,
    ///     false,
    ///     Some(0xFFFFFFFF),
    ///     None,
    /// );
    const MPEG2_TABLE: [u32; 256] = [
        0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2,
        0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3,
        0x3C8EA00A, 0x384FBDBD, 0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
        0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011,
        0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E,
        0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58, 0xBAEA46EF,
        0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D, 0xD4326D90,
        0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
        0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A,
        0xEC7DD02D, 0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C,
        0x2E003DC5, 0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13,
        0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE,
        0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
        0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA, 0xACA5C697, 0xA864DB20,
        0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F,
        0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
        0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055,
        0xFEF34DE2, 0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
        0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632,
        0x7EC98B85, 0x738AAD5C, 0x774BB0EB, 0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F,
        0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629, 0x2C9F00F0,
        0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B, 0x0315D626, 0x07D4CB91,
        0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
        0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
        0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604,
        0xC960EBB3, 0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615,
        0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A,
        0x8CF30BAD, 0x81B02D74, 0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
        0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21, 0x7F436096, 0x7200464F,
        0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E,
        0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC, 0x3793A651,
        0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
        0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
        0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA,
        0xF9278673, 0xFDE69BC4, 0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5,
        0x9E7D9662, 0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668,
        0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
    ];

    /// This contains a table generated from the ISO-HDLC 32-bit polynomial
    /// Used to test the table generation code.
    /// Below is the configuration:
    /// let configuration = CRCConfiguration::<u32>::new(
    ///     "CRC-32/ISO-HDLC",
    ///     BitWidth::ThirtyTwo,
    ///     CRCEndianness::LSB,
    ///     0x04C11DB7,
    ///     true,
    ///     true,
    ///     Some(0xFFFFFFFF),
    ///     Some(0xFFFFFFFF),
    /// );
    const ISO_HDLC_TABLE: [u32; 256] = [
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
        0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
        0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D,
        0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
        0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
        0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC,
        0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
        0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
        0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB,
        0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
        0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE,
        0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
        0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
        0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
        0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
        0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268,
        0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0,
        0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8,
        0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
        0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
        0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
        0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
        0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE,
        0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
        0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D,
        0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
        0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
        0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
    ];

    #[test]
    fn optimized_build_msb_table_32_works() {
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32/MPEG-2",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            0x04C11DB7,
            false,
            Some(0xFFFFFFFF),
            None,
        );

        let table = optimized_build_msb_table_32(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, MPEG2_TABLE);
    }

    #[test]
    fn optimized_build_lsb_table_32_works() {
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32/ISO-HDLC",
            BitWidth::ThirtyTwo,
            CRCEndianness::LSB,
            0x04C11DB7,
            true,
            Some(0xFFFFFFFF),
            Some(0xFFFFFFFF),
        );

        let table = optimized_build_lsb_table_32(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, ISO_HDLC_TABLE);
    }

    #[test]
    fn optimized_build_msb_table_16_works() {
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16/CCITT",
            BitWidth::Sixteen,
            CRCEndianness::MSB,
            0x1021,
            true,
            None,
            None,
        );
        let table = optimized_build_msb_table_16(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, CCITT_TABLE);
    }

    #[test]
    fn optimized_build_lsb_table_16_works() {
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16/KERMIT",
            BitWidth::Sixteen,
            CRCEndianness::LSB,
            0x1021,
            true,
            None,
            None,
        );
        let table = optimized_build_lsb_table_16(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, KERMIT_TABLE);
    }

    #[test]
    fn build_table_msb_16_works() {
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16/CCITT",
            BitWidth::Sixteen,
            CRCEndianness::MSB,
            0x1021,
            true,
            None,
            None,
        );
        let table = build_table_16(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, CCITT_TABLE);
    }

    #[test]
    fn build_table_lsb_16_works() {
        let configuration = CRCConfiguration::<u16>::new(
            "CRC-16/KERMIT",
            BitWidth::Sixteen,
            CRCEndianness::LSB,
            0x1021,
            true,
            None,
            None,
        );
        let table = build_table_16(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, KERMIT_TABLE);
    }

    #[test]
    fn build_table_msb_32_works() {
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32/MPEG-2",
            BitWidth::ThirtyTwo,
            CRCEndianness::MSB,
            0x04C11DB7,
            false,
            Some(0xFFFFFFFF),
            None,
        );
        let table = build_table_32(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, MPEG2_TABLE);
    }

    #[test]
    fn build_table_lsb_32_works() {
        let configuration = CRCConfiguration::<u32>::new(
            "CRC-32/ISO-HDLC",
            BitWidth::ThirtyTwo,
            CRCEndianness::LSB,
            0x04C11DB7,
            true,
            Some(0xFFFFFFFF),
            Some(0xFFFFFFFF),
        );
        let table = build_table_32(&configuration);

        assert_eq!(table.len(), 256);
        assert_eq!(table, ISO_HDLC_TABLE);
    }

    // Just to remind ourselves how Rust range iterations work
    #[test]
    fn test_rust_range_iter() {
        let mut count = 0;

        for _j in 0..0 {
            count += 1;
        }
        assert_eq!(count, 0);

        count = 0;
        for _j in 0..1 {
            count += 1;
        }
        assert_eq!(count, 1);

        count = 0;
        for _j in 0..=0 {
            count += 1;
        }
        assert_eq!(count, 1);

        count = 0;
        for _j in 0..=1 {
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
