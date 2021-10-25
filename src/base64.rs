use lazy_static::lazy_static;
use std::collections::HashMap;
use std::convert::TryFrom;

lazy_static! {
    static ref BASE64_CODEPOINTS: HashMap<char, u32> = {
        let mut map = HashMap::new();
        map.insert('A', 0);
        map.insert('B', 1);
        map.insert('C', 2);
        map.insert('D', 3);
        map.insert('E', 4);
        map.insert('F', 5);
        map.insert('G', 6);
        map.insert('H', 7);
        map.insert('I', 8);
        map.insert('J', 9);
        map.insert('K', 10);
        map.insert('L', 11);
        map.insert('M', 12);
        map.insert('N', 13);
        map.insert('O', 14);
        map.insert('P', 15);
        map.insert('Q', 16);
        map.insert('R', 17);
        map.insert('S', 18);
        map.insert('T', 19);
        map.insert('U', 20);
        map.insert('V', 21);
        map.insert('W', 22);
        map.insert('X', 23);
        map.insert('Y', 24);
        map.insert('Z', 25);
        map.insert('a', 26);
        map.insert('b', 27);
        map.insert('c', 28);
        map.insert('d', 29);
        map.insert('e', 30);
        map.insert('f', 31);
        map.insert('g', 32);
        map.insert('h', 33);
        map.insert('i', 34);
        map.insert('j', 35);
        map.insert('k', 36);
        map.insert('l', 37);
        map.insert('m', 38);
        map.insert('n', 39);
        map.insert('o', 40);
        map.insert('p', 41);
        map.insert('q', 42);
        map.insert('r', 43);
        map.insert('s', 44);
        map.insert('t', 45);
        map.insert('u', 46);
        map.insert('v', 47);
        map.insert('w', 48);
        map.insert('x', 49);
        map.insert('y', 50);
        map.insert('z', 51);
        map.insert('0', 52);
        map.insert('1', 53);
        map.insert('2', 54);
        map.insert('3', 55);
        map.insert('4', 56);
        map.insert('5', 57);
        map.insert('6', 58);
        map.insert('7', 59);
        map.insert('8', 60);
        map.insert('9', 61);
        map.insert('+', 62);
        map.insert('/', 63);
        map.insert('=', 64);
        map

    };
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

pub fn base64_to_slice(base64_string: &str) -> Result<Vec<u8>, String> {
    if base64_string.len() % 4 != 0 {
        return Err("Base 64 string is not divisible by 4".to_string());
    }
    let mut output: Vec<u8> = vec![];

    for chunk in base64_string.as_bytes().chunks_exact(4) {
        let first = BASE64_CODEPOINTS[&(chunk[0] as char)];
        let second = BASE64_CODEPOINTS[&(chunk[1] as char)];
        let third = BASE64_CODEPOINTS[&(chunk[2] as char)];
        let fourth = BASE64_CODEPOINTS[&(chunk[3] as char)];
        let combined: u32 = (first << 18)  |
                            (second << 12) |
                            (third << 6)   |
                            fourth;
        let decoded: [u8; 4] = combined.to_ne_bytes();
        output.push(decoded[2]);
        if (chunk[2] as char) != '=' {
            output.push(decoded[1]);
        }
        if (chunk[3] as char) != '=' {
            output.push(decoded[0]);
        }
    }

    Ok(output)
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

    #[test]
    fn base64_encodes_length_two() {
        let slice = "he".as_bytes();
        let encoded = slice_to_base64(slice);
        assert_eq!(encoded, "aGU=".to_string());
    }

    #[test]
    fn base64_encodes_length_one() {
        let slice = "h".as_bytes();
        let encoded = slice_to_base64(slice);
        assert_eq!(encoded, "aA==".to_string());
    }

    #[test]
    fn base64_decodes() {
        let encoded = "aGV5";
        let decoded = base64_to_slice(&encoded).expect("should decode");
        let decoded_str = std::str::from_utf8(&decoded).expect("should serialize");
        assert_eq!(decoded_str, "hey");
    }

    #[test]
    fn base64_decodes_length_two() {
        let encoded = "aGU=";
        let decoded = base64_to_slice(&encoded).expect("should decode");
        let decoded_str = std::str::from_utf8(&decoded).expect("should serialize");
        assert_eq!(decoded_str, "he");
    }

    #[test]
    fn base64_decodes_length_one() {
        let encoded = "aA==";
        let decoded = base64_to_slice(&encoded).expect("should decode");
        let decoded_str = std::str::from_utf8(&decoded).expect("should serialize");
        assert_eq!(decoded_str, "h");
    }

}
