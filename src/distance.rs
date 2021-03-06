use lazy_static::lazy_static;
use std::path::{Path, PathBuf};

lazy_static! {
    pub static ref ENGLISH_ALPHABET: CharacterDistribution = {
        let file_path = Path::new("ascii_freq.txt");
        let alphabet = CharacterDistribution::from_file(file_path.to_path_buf())
            .expect("should unwrap the thing");

        alphabet
    };
}

pub fn hamming(lhs: &[u8], rhs: &[u8]) -> Result<usize, String> {
    if lhs.len() != rhs.len() {
        return Err("Lengths of string must match".to_string());
    }
    let mut acc: usize = 0;

    for (ch1, ch2) in lhs.iter().zip(rhs.iter()) {
        let xor = ch1 ^ ch2;
        for idx in 0..7u8 {
            let n = 1 << idx;
            if xor & n != 0 {
                acc += 1;
            }
        }
    }

    Ok(acc)
}

#[cfg(test)]
mod test {
    use super::hamming;

    #[test]
    fn test_hamming() {
        let distance = hamming("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
            .expect("should compute");
        assert_eq!(distance, 37);
    }
}

/// Encapsulates a HashMap which maps ASCII characters to their frequencies
#[derive(Debug)]
pub struct CharacterDistribution {
    /// ASCII index to frequency
    frequencies: [f64; 256],
}

impl CharacterDistribution {
    fn new() -> Self {
        Self {
            frequencies: [0.0; 256],
        }
    }

    /// assumes the file is line delimited with [ascii index]:freq
    fn from_file(path: PathBuf) -> Result<Self, std::io::Error> {
        let mut dist = Self::new();

        let contents = std::fs::read_to_string(path)?;
        for line in contents.split('\n') {
            let split_line: Vec<&str> = line.split(':').collect();
            if split_line.len() != 2 {
                continue;
            }
            let index: usize = split_line[0].parse().expect("it should be a usize");
            let value: f64 = split_line[1].parse().expect("it should be a float");
            dist.frequencies[index] = value;
        }

        Ok(dist)
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut dist = Self::new();

        for b in bytes {
            let index = *b as usize;
            dist.frequencies[index] += 1.0;
        }

        dist
    }

    #[allow(dead_code)]
    pub fn letters_in_common(&self, other: &Self) -> usize {
        let mut common = 0;

        for point in 0..=255 {
            if self.frequencies[point] > 0.0 && other.frequencies[point] > 0.0 {
                common += 1;
            }
        }

        common
    }

    pub fn from_text(text: &str) -> Self {
        let mut dist = Self::new();

        for ch in text.chars() {
            if !ch.is_ascii() {
                continue;
            }
            let index = ch as usize;
            dist.frequencies[index] += 1.0;
        }
        let total_count: f64 = text.len() as f64;
        for index in 0..256 {
            dist.frequencies[index] = dist.frequencies[index] / total_count;
        }

        dist
    }

    /// compares using euclidean distance between two character distributions
    pub fn compare(&self, other: &Self) -> f64 {
        let mut sum: f64 = 0.0;
        for (p, q) in self.frequencies.iter().zip(other.frequencies.iter()) {
            let diff = p - q;
            sum += f64::powi(diff, 2);
        }

        f64::sqrt(sum)
    }
}
