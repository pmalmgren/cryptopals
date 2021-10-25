use lazy_static::lazy_static;
use std::collections::HashMap;

#[derive(Debug)]
pub enum HexDecodeError {
    OddLengthInput,
    InvalidHexDigit(String),
}

lazy_static! {
    static ref HEX_ALPHABET: HashMap<u8, char> = {
        let mut map = HashMap::new();
        map.insert(0, '0');
        map.insert(1, '1');
        map.insert(2, '2');
        map.insert(3, '3');
        map.insert(4, '4');
        map.insert(5, '5');
        map.insert(6, '6');
        map.insert(7, '7');
        map.insert(8, '8');
        map.insert(9, '9');
        map.insert(10, 'a');
        map.insert(11, 'b');
        map.insert(12, 'c');
        map.insert(13, 'd');
        map.insert(14, 'e');
        map.insert(15, 'f');
        map
    };
}

impl std::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexDecodeError::OddLengthInput => write!(f, "Received an odd length input"),
            HexDecodeError::InvalidHexDigit(digit) => write!(f, "Invalid hex digit {}", digit),
        }
    }
}
impl std::error::Error for HexDecodeError {}

pub fn bytes_to_hex_str(bytes: &[u8]) -> String {
    let mut hex_str = String::with_capacity(bytes.len() * 2);
    for byte in bytes.into_iter() {
        let upper = (byte & 0xF0) >> 4;
        let lower = byte & 0xF;

        let first = HEX_ALPHABET
            .get(&upper)
            .expect(format!("Invalid hex value {}", upper).as_str());
        let second = HEX_ALPHABET
            .get(&lower)
            .expect(format!("Invalid hex value {}", lower).as_str());
        hex_str.push(*first);
        hex_str.push(*second);
    }

    hex_str
}

pub fn hex_str_to_bytes(hex: &str) -> Result<Vec<u8>, HexDecodeError> {
    if hex.len() % 2 != 0 {
        return Err(HexDecodeError::OddLengthInput);
    }

    let chars: Vec<char> = hex.chars().collect();
    let chunks = chars.chunks(2);
    let mut digits: Vec<u8> = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let digit_str = format!("{}{}", chunk[0], chunk[1]);
        digits.push(
            u8::from_str_radix(&digit_str, 16)
                .map_err(|_e| HexDecodeError::InvalidHexDigit(digit_str))?,
        );
    }
    Ok(digits)
}
