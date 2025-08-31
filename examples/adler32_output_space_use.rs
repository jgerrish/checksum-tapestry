//! Example of using the Adler-32 checksum and a simple visualization
//! of it's weaknesses with small message sizes.
//! This doesn't show there are weaknesses with any degree of certainty,
//! it only shows a rough visualization.
//! Further statistical tests would need to be run to show that.
use std::time::{SystemTime, UNIX_EPOCH};

use checksum_tapestry::adler32::Adler32;
use checksum_tapestry::crc::{BitOrder, BitWidth, CRCConfiguration, CRC};
use checksum_tapestry::Checksum;

const NUM_EXPERIMENTS: u32 = 1000;
const NUM_BINS: u8 = 10;
const MESSAGE_SIZE: usize = 50;

/// Use the CRC code as a crude PRNG
/// It's not secure, but it works for the purposes here as an example.
/// If you want to substitute another algorithm, feel free to and
/// enjoy hacking!
fn prng(state: &mut CRC<u32>) -> u32 {
    state.update((state.state() >> 24) as u8)
}

/// Run an experiment for a given checksum algorithm.
/// Generates a set of random byte strings, and then calculates the checksum for that data.
/// Repeats this several times and returns the data.
fn run_experiment(
    prng_crc: &mut CRC<u32>,
    checksum: &mut dyn Checksum<u32>,
) -> [u32; NUM_EXPERIMENTS as usize] {
    let mut random_buffer: [u8; MESSAGE_SIZE] = [0; MESSAGE_SIZE];
    let mut experiments: [u32; NUM_EXPERIMENTS as usize] = [0; NUM_EXPERIMENTS as usize];

    // Run the experiments
    for i in 0..NUM_EXPERIMENTS {
        // Generate a random message string
        let mut last: u32;
        for item in &mut random_buffer {
            last = prng(prng_crc);
            *item = (last >> 24) as u8;
        }

        // Use the adler-32 checksum here
        let result = checksum.compute(&random_buffer);
        checksum.reset();

        experiments[i as usize] = result;
    }

    experiments
}

/// Draw a histogram from experiment data
fn draw_histogram(experiments: [u32; NUM_EXPERIMENTS as usize]) {
    let bin_boundary = NUM_BINS as f32 / u32::MAX as f32;
    let mut bins: [u32; NUM_BINS as usize] = [0; NUM_BINS as usize];

    for i in 0..NUM_EXPERIMENTS {
        let bin = (experiments[i as usize] as f32 * bin_boundary).floor();
        bins[bin as usize] += 1;
    }

    // graph width in characters
    let width = 55;

    // The histogram code assumes the distribution is uniform for display purposes
    // For the adler-32 case, this isn't true, but still do the calculation
    let avg_stars_per_bin = NUM_EXPERIMENTS as f32 / NUM_BINS as f32;
    // Set aside some extra space
    let avg_stars_per_bin = avg_stars_per_bin * 1.8;
    let line_div = avg_stars_per_bin / width as f32;

    for i in 0..NUM_BINS {
        let total = bins[i as usize];
        let start = (u32::MAX as f32 / NUM_BINS as f32) * i as f32;
        let end = (u32::MAX as f32 / NUM_BINS as f32) * (i + 1) as f32;
        print!("0x{:08X} - 0x{:08X}: ", start as u32, end as u32);
        let stars_to_print: u32 = (total as f32 / line_div).floor() as u32;
        for _j in 0..stars_to_print {
            print!("*");
        }
        println!();
    }
}

fn main() {
    // Use a CRC as a PRNG
    let t = SystemTime::now();
    let t = t.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let seed: u32 = (t % (u32::MAX as u128 + 1)) as u32;
    let mut prng_crc = CRC::<u32>::new(
        CRCConfiguration::<u32>::new(
            "CRC-32/ISO-HDLC",
            BitWidth::ThirtyTwo,
            BitOrder::LSBFirst,
            0x04C11DB7,
            true,
            Some(seed),
            Some(0xFFFFFFFF),
        ),
        true,
    );

    // Run an Adler-32 experiment, showing a histogram of values
    let mut adler32 = Adler32::default();
    let experiments = run_experiment(&mut prng_crc, &mut adler32);
    println!("Adler32 Histogram");
    draw_histogram(experiments);

    println!();

    // Run a CRC32 experiment, showing a histogram of values
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
    let experiments = run_experiment(&mut prng_crc, &mut crc32);
    println!("CRC32 Histogram");
    draw_histogram(experiments);
}
