use crate::error::CliError;
use std::env::args;
use std::error::Error;
use std::path::Path;

mod base64;
mod block_crypto;
mod distance;
mod error;
mod hex;
mod otp;
mod xor;

fn decode_single(bytes: &[u8], single: u8) -> Result<(String, f64), Box<dyn Error>> {
    let english = &distance::ENGLISH_ALPHABET;
    let decoded = xor::single_xor(&bytes, single);
    let decoded_str = std::str::from_utf8(&decoded)?;
    let decoded_distribution = distance::CharacterDistribution::from_text(decoded_str);
    Ok((
        decoded_str.to_string(),
        english.compare(&decoded_distribution),
    ))
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
        println!(
            "Smallest Euclidean distance letter {} = {}",
            smallest.0, smallest.1
        );
        let decoded = xor::single_xor(&decoded, smallest.0 as u8);
        let decoded_str = std::str::from_utf8(&decoded)?;
        println!("Decoded = {}", decoded_str);
    }

    Ok(())
}

fn challenge4() -> Result<(), Box<dyn Error>> {
    let challenge_file_contents = std::fs::read_to_string(Path::new("4.txt"))?;

    let mut smallest: Vec<(String, f64)> = vec![];
    let lines: Vec<String> = challenge_file_contents
        .split('\n')
        .map(String::from)
        .collect();

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
            smallest.sort_by(|lhs, rhs| {
                lhs.1
                    .partial_cmp(&rhs.1)
                    .expect(format!("Why?? {} > {}", lhs.1, rhs.1).as_str())
            });
            key.push(smallest[0].0);
        }

        let cracked = xor::repeating_xor(cipher, &key);

        match std::str::from_utf8(&cracked) {
            Err(_e) => None,
            Ok(s) => Some((s.into(), key)),
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

        let dist1 =
            distance::hamming(first, second).expect("should get the distance") as f64 / size as f64;
        let dist2 =
            distance::hamming(third, fourth).expect("should get the distance") as f64 / size as f64;
        let dist3 =
            distance::hamming(fifth, sixth).expect("should get the distance") as f64 / size as f64;
        let distance = (dist1 + dist2 + dist3) / 3.0;

        min_size.push((size, distance));
    }

    min_size.sort_by(|lhs, rhs| {
        lhs.1
            .partial_cmp(&rhs.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

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
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
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
    println!(
        "Line {} has lowest average pairwise hamming distance: {:.4} and {} identical blocks",
        scores[0].0, scores[0].1, scores[0].2
    );
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
    let plaintext_vec: Vec<Vec<char>> = (0..10)
        .map(|_x| "YELLOW_SUBMARINE".to_string().chars().collect())
        .collect();
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

    let block_size = block_crypto::discover_blocksize(&|bytes: &[u8]| oracle.encrypt(bytes))?;
    println!("Discovered block size = {}", block_size);

    let input = yellow_submarine_10_times();
    let encrypted = oracle.encrypt(&input)?;
    assert!(block_crypto::is_ecb(block_size, &encrypted));

    let mut plaintext: String = "".to_string();
    let mut pad: Vec<u8> = (0..block_size - 1).map(|_| 'A' as u8).collect();

    for (idx, _) in encrypted.chunks(block_size).enumerate() {
        let result = block_crypto::decrypt_block(idx, block_size, 0, &pad, &|bytes: &[u8]| {
            oracle.encrypt(bytes)
        });
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

fn challenge13() -> Result<(), Box<dyn Error>> {
    // blocks: ["email=abc@ab.com"], ["admin\x0B..."], ...
    let email = "abc@ab.comadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B";
    // blocks: ["email=1234567@a.", "com&uid=10&role=", "user"]
    let template = "1234567@a.com";
    let mut encrypted_template = block_crypto::UserProfile::profile_for(template).encrypt()?[0..32].to_vec();
    let admin_block = &block_crypto::UserProfile::profile_for(email).encrypt()?[16..32];
    encrypted_template.extend_from_slice(admin_block);

    let admin_profile = block_crypto::UserProfile::decrypt(&encrypted_template)?;
    println!("{:?}", admin_profile);

    Ok(())
}

mod challenge14 {
    use std::error::Error;
    use crate::error::CliError;

    #[derive(Debug)]
    pub struct RandomPad {
        pub controlled_block: usize,
        pub pad_bytes: Vec<u8>
    }

    /// Given an oracle which pads random bytes at the beginning, find the pad needed
    /// to give the attacker control over the next block, which is the start of the
    /// ciphertext.
    /// Algorithm (find suspect block):
    /// 1. Get all encrypted blocks
    /// 2. Encrypt a single attacker controlled byte
    /// 3. Find the first block in the new cipher text different than the old
    ///
    /// After we know which block to start with
    /// 1. Find the suspect block index
    /// 2. Loop: Add a byte at a time
    /// 3. Find the first block in the new cipher text different than the old
    /// 4. Stop when it changes
    pub fn detect_random_pad<F>(block_size: usize, oracle: &F) -> Result<RandomPad, Box<dyn Error>>
        where F: Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>>
    {
        let encrypted_blank = oracle("".as_bytes())?; 
        let encrypted_one = oracle("a".as_bytes())?; 
        let mut suspect_chunk = -1;
        let mut last_chunk = vec![0; block_size];
        for (idx, (chunk, chunk2)) in encrypted_blank.chunks(block_size).zip(encrypted_one.chunks(block_size)).enumerate() {
            if chunk != chunk2 {
                suspect_chunk = idx as i32;
                last_chunk = chunk.to_vec();
                break;
            }
        }

        if suspect_chunk == -1 {
            return Err(CliError("Error finding where attacker controlled bytes start".into()).into());
        }

        for nbytes in 1..(block_size + 2) {
            let pad_bytes: Vec<u8> = (0..nbytes)
                .map(|_| 'A' as u8)
                .collect();
            let encrypted = oracle(&pad_bytes)?;
            let controlled_block = suspect_chunk as usize;
            let start = controlled_block * block_size;
            let end = start + block_size;
            let chunk = &encrypted[start..end]; 
            if chunk == &last_chunk {
                let pad_bytes = pad_bytes[0..nbytes-1].to_vec();
                return Ok(RandomPad { controlled_block: controlled_block + 1, pad_bytes });
            }
            last_chunk = chunk.to_vec();
        }

        return Err(CliError("Didn't find random bytes".into()).into());
    }

    #[cfg(test)]
    mod test {
        use super::*;

        fn fake_oracle(pad: usize, b: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            let fake_message = "YELLOW SUBMARINEYELLOW SUBMARINE".as_bytes();
            let mut fake_ciphertext: Vec<u8> = (0..pad)
                .map(|_| 'R' as u8)
                .collect();
            fake_ciphertext.extend_from_slice(b);
            fake_ciphertext.extend_from_slice(&fake_message);
            let rem = fake_ciphertext.len() % 16;
            if rem > 0 {
                let bytes_to_append = 16 - rem;
                let bytes: Vec<u8> = (0..bytes_to_append)
                    .map(|_| 'P' as u8)
                    .collect();
                fake_ciphertext.extend_from_slice(&bytes);
            }
            assert!(fake_ciphertext.len() % 16 == 0);
            Ok(fake_ciphertext)
        }

        #[test]
        fn test_detect_random_pad() {
            let res = detect_random_pad(16, &|b: &[u8]| fake_oracle(5, b)).expect("should find where attacker controlled bytes start");
            assert_eq!(res.controlled_block, 1);
            assert_eq!(res.pad_bytes.len(), 11);
            let fake_encrypted_bytes = fake_oracle(5, &res.pad_bytes).expect("should fake encrypt the bytes");
            let str0 = std::str::from_utf8(&fake_encrypted_bytes[0..16]).expect("should produce a string");
            let str1 = std::str::from_utf8(&fake_encrypted_bytes[16..32]).expect("should produce a string");
            let str2 = std::str::from_utf8(&fake_encrypted_bytes[32..48]).expect("should produce a string");
            assert_eq!(str0, "RRRRRAAAAAAAAAAA");
            assert_eq!(str1, "YELLOW SUBMARINE");
            assert_eq!(str2, "YELLOW SUBMARINE");
        }

        #[test]
        fn test_detect_random_pad_one() {
            let res = detect_random_pad(16, &|b: &[u8]| fake_oracle(15, b)).expect("should find where attacker controlled bytes start");
            assert_eq!(res.controlled_block, 1);
            assert_eq!(res.pad_bytes.len(), 1);
            let fake_encrypted_bytes = fake_oracle(15, &res.pad_bytes).expect("should fake encrypt the bytes");
            let str0 = std::str::from_utf8(&fake_encrypted_bytes[0..16]).expect("should produce a string");
            let str1 = std::str::from_utf8(&fake_encrypted_bytes[16..32]).expect("should produce a string");
            let str2 = std::str::from_utf8(&fake_encrypted_bytes[32..48]).expect("should produce a string");
            assert_eq!(str0, "RRRRRRRRRRRRRRRA");
            assert_eq!(str1, "YELLOW SUBMARINE");
            assert_eq!(str2, "YELLOW SUBMARINE");
        }

        #[test]
        fn test_detect_random_pad_zero() {
            let res = detect_random_pad(16, &|b: &[u8]| fake_oracle(0, b)).expect("should find where attacker controlled bytes start");
            assert_eq!(res.controlled_block, 1);
            assert_eq!(res.pad_bytes.len(), 16);
            let fake_encrypted_bytes = fake_oracle(0, &res.pad_bytes).expect("should fake encrypt the bytes");
            let str0 = std::str::from_utf8(&fake_encrypted_bytes[0..16]).expect("should produce a string");
            let str1 = std::str::from_utf8(&fake_encrypted_bytes[16..32]).expect("should produce a string");
            let str2 = std::str::from_utf8(&fake_encrypted_bytes[32..48]).expect("should produce a string");
            assert_eq!(str0, "AAAAAAAAAAAAAAAA");
            assert_eq!(str1, "YELLOW SUBMARINE");
            assert_eq!(str2, "YELLOW SUBMARINE");
        }

        #[test]
        fn test_detect_random_pad_sixteen() {
            let res = detect_random_pad(16, &|b: &[u8]| fake_oracle(16, b)).expect("should find where attacker controlled bytes start");
            assert_eq!(res.controlled_block, 2);
            assert_eq!(res.pad_bytes.len(), 16);
            let fake_encrypted_bytes = fake_oracle(16, &res.pad_bytes).expect("should fake encrypt the bytes");
            let str0 = std::str::from_utf8(&fake_encrypted_bytes[0..16]).expect("should produce a string");
            let str1 = std::str::from_utf8(&fake_encrypted_bytes[16..32]).expect("should produce a string");
            let str2 = std::str::from_utf8(&fake_encrypted_bytes[32..48]).expect("should produce a string");
            let str3 = std::str::from_utf8(&fake_encrypted_bytes[48..64]).expect("should produce a string");
            assert_eq!(str0, "RRRRRRRRRRRRRRRR");
            assert_eq!(str1, "AAAAAAAAAAAAAAAA");
            assert_eq!(str2, "YELLOW SUBMARINE");
            assert_eq!(str3, "YELLOW SUBMARINE");
        }
    }
}

fn challenge14() -> Result<(), Box<dyn Error>> {
    let oracle = block_crypto::Oracle::new()?;
    let block_size = block_crypto::discover_blocksize(&|bytes: &[u8]| oracle.encrypt_prefix(bytes))?;
    println!("Discovered block size = {}", block_size);

    let random_pad = challenge14::detect_random_pad(block_size, &|bytes: &[u8]| oracle.encrypt_prefix(bytes))?;
    println!("Discovered random bytes = {:?}", random_pad);

    let mut _plaintext: String = "".to_string();
    let pad: Vec<u8> = (0..block_size - 1).map(|_| 'A' as u8).collect();
    // the input looks like this:
    // [RB, RB1, RB2, RB3, RB4, P1, P2, P3] [B1, B2, B3, B4, B5, B6, B7, B8]
    // where RB = random byte, P = our pad bytes
    // attack 1:
    // [RB, RB1, RB2, RB3, RB4, P1, P2, P3] [A, A, A, A, A, A, A, B1] [B2, B3, B4, B5, B6, B7, B8, B9]
    // attack 2:
    // [RB, RB1, RB2, RB3, RB4, P1, P2, P3] [A, A, A, A, A, A, A, B1] [B2, B3, B4, B5, B6, B7, B8, B9]
    let decrypted = block_crypto::decrypt_block(random_pad.controlled_block, block_size, random_pad.controlled_block, &pad, &|bytes: &[u8]| {
        let mut to_encrypt = random_pad.pad_bytes.clone();
        to_encrypt.extend_from_slice(bytes);
        oracle.encrypt_prefix(&to_encrypt)
    });

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
        "challenge13" => challenge13(),
        "challenge14" => challenge14(),
        cmd => {
            eprintln!("Unknown subcommand {}", cmd);
            return Err(CliError("Unknown command".to_string()).into());
        }
    }
}
