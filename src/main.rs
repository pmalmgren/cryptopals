use std::env::args;
use std::error::Error;
use std::path::Path;
use std::collections::HashMap;
use std::convert::TryInto;
use crate::error::CliError;

mod base64;
mod hex;
mod distance;
mod otp;
mod xor;
mod error;
mod block_crypto;

fn decode_single(bytes: &[u8], single: u8) -> Result<(String, f64), Box<dyn Error>> {
    let english = &distance::ENGLISH_ALPHABET;
    let decoded = xor::single_xor(&bytes, single);
    let decoded_str = std::str::from_utf8(&decoded)?;
    let decoded_distribution = distance::CharacterDistribution::from_text(decoded_str);
    Ok((decoded_str.to_string(), english.compare(&decoded_distribution)))
}

fn challenge1(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() > 1 {
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        println!("{}", base64::slice_to_base64(&decoded));
    }

    Ok(())
}

fn challenge2(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() > 2 {
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        let decoded2 = hex::hex_str_to_bytes(&args[2])?;
        let xord = xor::fixed_xor(&decoded, &decoded2)?;
        println!("{}", hex::bytes_to_hex_str(&xord));
    }

    Ok(())
}

fn challenge3(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() > 1 {
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        let mut smallest = ('-', 1.0);
        for ch in ASCII_LOWER.iter() {
            let distance = decode_single(&decoded, *ch as u8)?;
            if distance.1 < smallest.1 {
                smallest = (*ch, distance.1);
            }
        }
        println!("Smallest Euclidean distance letter {} = {}", smallest.0, smallest.1);
        let decoded = xor::single_xor(&decoded, smallest.0 as u8);
        let decoded_str = std::str::from_utf8(&decoded)?;
        println!("Decoded = {}", decoded_str);
    }

    Ok(())
}

fn challenge4() -> Result<(), Box<dyn Error>> {
    let challenge_file_contents = std::fs::read_to_string(Path::new("4.txt"))?;

    let mut smallest: Vec<(String, f64)> = vec![];
    let lines: Vec<String> = challenge_file_contents.split('\n').map(String::from).collect();

    for (_index, line) in lines.iter().enumerate() {
        let decoded = hex::hex_str_to_bytes(&line)?;
        for ch in 0u8..255 {
            if let Ok(distance) = decode_single(&decoded, ch) {
                smallest.push(distance);
            }
        }
    }
    smallest.sort_by(|lhs, rhs| lhs.1.partial_cmp(&rhs.1).unwrap());

    println!("{:?}", smallest[0]);

    Ok(())
}

fn challenge5(args: &[String]) {
    if args.len() != 2 {
        eprintln!("Give me an input filename and a key. Got: {:?}", args);
        return;
    }
    let input = std::fs::read_to_string(Path::new(&args[0])).unwrap();
    let key = &args[1];
    let output = xor::repeating_xor(&input.as_bytes(), key.as_bytes());
    let output2 = xor::repeating_xor(&output, key.as_bytes());
    println!("{}", hex::bytes_to_hex_str(&output));
    println!("{:?}", std::str::from_utf8(&output2));
}

mod challenge6 {
    use super::{decode_single, xor};

    fn transpose_blocks(key_size: usize, input: &[u8]) -> Vec<Vec<u8>> {
        let est_block_size = input.len() / key_size;
        let mut transposed_blocks: Vec<Vec<u8>> = Vec::with_capacity(key_size);
        for _ in 0..key_size {
            transposed_blocks.push(Vec::with_capacity(est_block_size));
        }
        // [13, 34, 23, 42, 21, 41, 42, 21]
        // key_size = 2
        // [13, 23, 21, 42]
        // [34, 42, 41, 21]
        for chunk in input.chunks(key_size) {
            for (block_num, byte) in chunk.iter().enumerate() {
                transposed_blocks[block_num].push(*byte);
            }
        }

        transposed_blocks
    }

    #[cfg(test)]
    mod test {
        use super::transpose_blocks;

        #[test]
        fn transpose() {
            let input = [13, 34, 23, 42, 21, 41, 42, 21];
            let key_size = 2;

            let transposed_blocks = transpose_blocks(key_size, &input);

            assert_eq!(transposed_blocks[0], [13, 23, 21, 42]);
            assert_eq!(transposed_blocks[1], [34, 42, 41, 21]);
        }
    }

    pub fn try_crack(key_size: usize, cipher: &[u8]) -> Option<(String, Vec<u8>)> {
        let transposed_blocks = transpose_blocks(key_size, cipher);
        let mut key: Vec<u8> = vec![];

        for block in transposed_blocks.iter() {
            let mut smallest: Vec<(u8, f64)> = vec![];
            for ch in 0u8..255 {
                if let Ok(distance) = decode_single(&block, ch) {
                    smallest.push((ch, distance.1));
                }
            }
            smallest.sort_by(|lhs, rhs| lhs.1.partial_cmp(&rhs.1).expect(
                format!("Why?? {} > {}", lhs.1, rhs.1).as_str()
            ));
            key.push(smallest[0].0);
        }
        
        let cracked = xor::repeating_xor(cipher, &key);

        match std::str::from_utf8(&cracked) {
            Err(_e) => None,
            Ok(s) => Some((s.into(), key))
        }
    }
}

fn challenge6() {
    let input: String = std::fs::read_to_string(Path::new("6.txt"))
        .unwrap()
        .chars()
        .filter(|c| *c != '\n' || *c != '\r')
        .collect();
    let input = input.replace('\n', "");
    let decoded = base64::base64_to_bytes(&input).expect("should decode");

    let mut min_size: Vec<(usize, f64)> = vec![];
    for size in 2..50 {
        let mut chunks = decoded.chunks(size);
        let first = chunks.next().expect("Should have chunk 1");
        let second = chunks.next().expect("Should have chunk 2");
        let third = chunks.next().expect("Should have chunk 3");
        let fourth = chunks.next().expect("Should have chunk 4");
        let fifth = chunks.next().expect("Should have chunk 5");
        let sixth = chunks.next().expect("Should have chunk 6");

        let dist1 = distance::hamming(first, second).expect("should get the distance") as f64 / size as f64;
        let dist2 = distance::hamming(third, fourth).expect("should get the distance") as f64 / size as f64;
        let dist3 = distance::hamming(fifth, sixth).expect("should get the distance") as f64 / size as f64;
        let distance = (dist1 + dist2 + dist3) / 3.0;
        
        min_size.push((size, distance));
    }

    min_size.sort_by(|lhs, rhs| lhs.1.partial_cmp(&rhs.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut attempted_cracks: Vec<(String, Vec<u8>, f64)> = vec![];
    for size in min_size[0..5].into_iter() {
        println!("Trying chunk size {}", size.0);
        if let Some(success) = challenge6::try_crack(size.0, &decoded) {
            let dist = distance::CharacterDistribution::from_text(&success.0);
            let distance = distance::ENGLISH_ALPHABET.compare(&dist);
            attempted_cracks.push((success.0, success.1, distance));
        }
    }

    attempted_cracks.sort_by(|lhs, rhs| lhs.2.partial_cmp(&rhs.2).unwrap());
    println!("Key = {:?}", attempted_cracks[0].1);
    println!("** Cracked **");
    println!("{}", attempted_cracks[0].0);
}

static ASCII_LOWER: [char; 52] = [
    'a', 'b', 'c', 'd', 'e', 
    'f', 'g', 'h', 'i', 'j', 
    'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 
    'u', 'v', 'w', 'x', 'y', 
    'z', 'A', 'B', 'C', 'D',
    'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W' ,'X',
    'Y', 'Z'
];

fn challenge7() {
    let input: String = std::fs::read_to_string(Path::new("7.txt"))
        .unwrap()
        .chars()
        .filter(|c| *c != '\n' || *c != '\r')
        .collect();
    let input = input.replace('\n', "");
    let decoded = base64::base64_to_bytes(&input).expect("should decode");
    let key = "YELLOW SUBMARINE".as_bytes();
    let output = block_crypto::decrypt_ecb(key, &decoded).unwrap();
    println!("{}", std::str::from_utf8(&output).unwrap());
}

fn challenge8() {
    let input: String = std::fs::read_to_string(Path::new("8.txt")).unwrap();
    let ciphers: Vec<Vec<u8>> = input
        .split('\n')
        .map(|s| hex::hex_str_to_bytes(s).expect("should unwrap"))
        .collect();
    
    let mut scores: Vec<(usize, f64, usize)> = vec![];
    for (line, cipher) in ciphers.into_iter().enumerate() {
        if cipher.len() == 0 {
            continue;
        }
        let mut count = 0.0;
        let mut dist = 0.0;
        let mut identical_blocks = 0;
        for (idx, chunk) in cipher.chunks_exact(16).enumerate() {
            for (idx2, chunk2) in cipher.chunks_exact(16).enumerate() {
                if idx == idx2 {
                    continue;
                }
                if chunk == chunk2 {
                    identical_blocks += 1;
                }
                let block_dist = distance::hamming(&chunk, &chunk2).unwrap() as f64;
                count += 1.0;
                dist += block_dist;
            }
        }
        scores.push((line, dist / count, identical_blocks));
    }

    scores.sort_by(|lhs, rhs| lhs.1.partial_cmp(&rhs.1).unwrap());
    println!("Line {} has lowest average pairwise hamming distance: {:.4} and {} identical blocks", scores[0].0, scores[0].1, scores[0].2);
}

fn challenge9(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() != 2 {
        return Err(CliError("Give me a string to pad and a length".into()).into());
    }

    let mut block = args[0].as_bytes().to_vec();
    let orig_length = block.len();
    let pad_length: usize = args[1].parse()?;

    let padded = block_crypto::pad(&mut block, pad_length);

    for (idx, b) in padded.into_iter().enumerate() {
        if idx < orig_length {
            print!("{}", b as char);
        } else {
            print!("\\x{:02}", b);
        }
    }

    println!();

    Ok(())
}

fn challenge10() -> Result<(), Box<dyn Error>> {
    let input = std::fs::read_to_string(Path::new("10.txt"))?;
    let input = input.replace('\n', "");
    let input = base64::base64_to_bytes(&input)?;
    let iv: Vec<u8> = [0; 16].to_vec();
    let output = block_crypto::decrypt_cbc("YELLOW SUBMARINE".as_bytes(), &input, &iv)?;
    println!("{}", std::str::from_utf8(&output)?);
    Ok(())
}

fn yellow_submarine_10_times() -> Vec<u8> {
    let plaintext_vec: Vec<Vec<char>> = (0..10).map(|_x| "YELLOW_SUBMARINE".to_string().chars().collect()).collect();
    let plaintext: String = plaintext_vec.into_iter().flatten().collect();
    plaintext.into_bytes()
}

fn challenge11() -> Result<(), Box<dyn Error>> {
    let yellow_submarine = yellow_submarine_10_times();
    let encrypted = block_crypto::encryption_oracle(&yellow_submarine)?;

    let bytes = match encrypted {
        block_crypto::EncryptedText::Cbc(ref b) => b,
        block_crypto::EncryptedText::Ecb(ref b) => b,
    };

    if block_crypto::is_ecb(16, bytes) {
        assert!(encrypted.is_ecb());
    } else {
        assert!(encrypted.is_cbc());
    }

    Ok(())
}

fn challenge12() -> Result<(), Box<dyn Error>> {
    let oracle = block_crypto::Oracle::new()?;

    let block_size = block_crypto::discover_blocksize(&oracle)?;
    println!("Discovered block size = {}", block_size);

    let input = yellow_submarine_10_times();
    let encrypted = oracle.encrypt(&input)?;
    assert!(block_crypto::is_ecb(block_size, &encrypted));

    let mut plaintext: String = "".to_string();
    let mut pad: Vec<u8> = (0..block_size - 1).map(|_| 'A' as u8).collect();

    for (idx, _) in encrypted.chunks(block_size).enumerate() {
        let result = block_crypto::decrypt_block(idx, block_size, &oracle, &pad);
        match result {
            Ok(bytes) => {
                pad = bytes[1..].to_vec();
                let decryted_str = std::str::from_utf8(&bytes)?;
                plaintext.push_str(decryted_str);
            }
            Err(bytes) => {
                let decryted_str = std::str::from_utf8(&bytes)?;
                plaintext.push_str(decryted_str);
                break;
            }
        };
    }

    println!("Decrypted = {}", plaintext);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = args().collect();

    if args.len() <= 1 {
        eprintln!("Usage: [subcommand] [arguments]");
        return Err(CliError("Incorrect arguments".to_string()).into());
    }

    match args[1].as_ref() {
        "padproblem" => otp::one_time_pad_encrypt(&args[2..]),
        "challenge1" => challenge1(&args[1..]),
        "challenge2" => challenge2(&args[1..]),
        "challenge3" => challenge3(&args[1..]),
        "challenge4" => challenge4(),
        "challenge5" => Ok(challenge5(&args[2..])),
        "challenge6" => Ok(challenge6()),
        "challenge7" => Ok(challenge7()),
        "challenge8" => Ok(challenge8()),
        "challenge9" => challenge9(&args[2..]),
        "challenge10" => challenge10(),
        "challenge11" => challenge11(),
        "challenge12" => challenge12(),
        cmd => {
            eprintln!("Unknown subcommand {}", cmd);
            return Err(CliError("Unknown command".to_string()).into());
        }
    }
}
