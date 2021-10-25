use lazy_static::lazy_static;
use std::collections::HashMap;
use std::convert::TryFrom;

lazy_static! {
    static ref BASE64_ALPHABET: HashMap<u32, char> = {
        let mut map = HashMap::new();
        map.insert(0, 'A');
        map.insert(1, 'B');
        map.insert(2, 'C');
        map.insert(3, 'D');
        map.insert(4, 'E');
        map.insert(5, 'F');
        map.insert(6, 'G');
        map.insert(7, 'H');
        map.insert(8, 'I');
        map.insert(9, 'J');
        map.insert(10, 'K');
        map.insert(11, 'L');
        map.insert(12, 'M');
        map.insert(13, 'N');
        map.insert(14, 'O');
        map.insert(15, 'P');
        map.insert(16, 'Q');
        map.insert(17, 'R');
        map.insert(18, 'S');
        map.insert(19, 'T');
        map.insert(20, 'U');
        map.insert(21, 'V');
        map.insert(22, 'W');
        map.insert(23, 'X');
        map.insert(24, 'Y');
        map.insert(25, 'Z');
        map.insert(26, 'a');
        map.insert(27, 'b');
        map.insert(28, 'c');
        map.insert(29, 'd');
        map.insert(30, 'e');
        map.insert(31, 'f');
        map.insert(32, 'g');
        map.insert(33, 'h');
        map.insert(34, 'i');
        map.insert(35, 'j');
        map.insert(36, 'k');
        map.insert(37, 'l');
        map.insert(38, 'm');
        map.insert(39, 'n');
        map.insert(40, 'o');
        map.insert(41, 'p');
        map.insert(42, 'q');
        map.insert(43, 'r');
        map.insert(44, 's');
        map.insert(45, 't');
        map.insert(46, 'u');
        map.insert(47, 'v');
        map.insert(48, 'w');
        map.insert(49, 'x');
        map.insert(50, 'y');
        map.insert(51, 'z');
        map.insert(52, '0');
        map.insert(53, '1');
        map.insert(54, '2');
        map.insert(55, '3');
        map.insert(56, '4');
        map.insert(57, '5');
        map.insert(58, '6');
        map.insert(59, '7');
        map.insert(60, '8');
        map.insert(61, '9');
        map.insert(62, '+');
        map.insert(63, '/');
        map.insert(64, '=');
        map
    };
}

fn unwrap_bits(input: u32) -> char {
    let val = BASE64_ALPHABET
        .get(&input)
        .expect(format!("input: {} not found", input).as_str());
    *val
}

pub fn slice_to_base64(hex: &[u8]) -> String {
    hex.chunks(3)
        .map(|chunk| chunk.to_vec())
        .map(|mut chunk: Vec<u8>| -> String {
            let pad_bytes: usize = 3 - chunk.len();
            for _x in 0..pad_bytes + 1 {
                chunk.push(0);
            }
            let concatenated_chunks = <[u8; 4]>::try_from(chunk).unwrap();
            let num = u32::from_be_bytes(concatenated_chunks);
            let first = unwrap_bits((num & 0xfc000000) >> 26);
            let second = unwrap_bits((num & 0x3f00000) >> 20);
            let third = if pad_bytes >= 2 {
                '='
            } else {
                unwrap_bits((num & 0xfc000) >> 14)
            };
            let fourth = if pad_bytes >= 1 {
                '='
            } else {
                unwrap_bits((num & 0x3f00) >> 8)
            };

            let mut encoded = String::new();
            encoded.push(first);
            encoded.push(second);
            encoded.push(third);
            encoded.push(fourth);
            encoded
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn base64_encodes() {
        let slice = "hey".as_bytes();
        let encoded = slice_to_base64(slice);
        assert_eq!(encoded, "aGV5".to_string());
    }
}
