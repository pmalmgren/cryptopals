use openssl::symm::{Cipher, Crypter, Mode, decrypt, encrypt};
use super::CliError;
use crate::xor::fixed_xor;
use rand::Rng;
use crate::base64;
use std::error::Error;
use std::collections::HashMap;

pub fn pad(input: &[u8], length: usize) -> Vec<u8> {
    if input.len() >= length {
        return input.to_vec();
    }
    let mut output: Vec<u8> = Vec::with_capacity(length);
    output.extend_from_slice(input);
    let bytes_to_pad: u8 = (length - input.len()) as u8;
    for _ in 0..bytes_to_pad {
        output.push(bytes_to_pad);
    }
    output
}

fn remove_padding(input: &mut Vec<u8>, key_len: u8) {
    let mut padding_start: Option<usize> = None;
    let mut detected_pad_byte: Option<u8> = None;
    for (idx, byte) in input.into_iter().enumerate() {
        match (padding_start, detected_pad_byte) {
            (Some(_start), Some(pad_byte)) => {
                if *byte != pad_byte {
                    padding_start = None;
                    detected_pad_byte = None;
                }
            },
            (None, None) => {
                if *byte < key_len {
                    detected_pad_byte = Some(*byte);
                    padding_start = Some(idx);
                }
            },
            _ => panic!("unreachable")
        }
    }

    match (padding_start, detected_pad_byte) {
        (Some(start), Some(pad_byte)) if (input.len() - start) as u8 == pad_byte => {
            input.truncate(start);
        },
        _ => {}
    };
}

pub fn encrypt_ecb(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encrypted: Vec<u8> = vec![];
    let cipher = Cipher::aes_128_ecb();
    for chunk in input.chunks(key.len()) {
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
        let mut output = vec![0; key.len() * 2];
        let padding = key.len() - chunk.len();
        if padding > 0 {
            let padded_chunk = pad(chunk, key.len());
            encrypter.update(&padded_chunk, &mut output)?;
        } else {
            encrypter.update(&chunk, &mut output)?;
        };
        encrypted.extend_from_slice(&output[0..key.len()]);
    }
    Ok(encrypted)
}

pub fn decrypt_ecb(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypted: Vec<u8> = vec![];
    let num_chunks = input.len() / key.len();
    for (chunk_num, chunk) in input.chunks(key.len()).enumerate() {
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
        let mut output = vec![0; key.len() * 2];
        decrypter.update(&chunk, &mut output)?;
        let mut output = output[0..key.len()].to_vec();
        if chunk_num == num_chunks - 1 {
            remove_padding(&mut output, key.len() as u8);
            decrypted.extend_from_slice(&output);
        } else {
            decrypted.extend_from_slice(&output);
        }
    }
    Ok(decrypted)
}

pub fn decrypt_cbc(key: &[u8], input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if iv.len() != key.len() {
        return Err(CliError("Key and IV length mismatch".into()).into());
    }
    let cipher = Cipher::aes_128_ecb();
    let mut previous_chunk = iv;
    let mut decrypted: Vec<u8> = vec![];
    let num_chunks = input.len() / key.len();
    for (chunk_num, chunk) in input.chunks(key.len()).enumerate() {
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
        let mut output = vec![0; key.len() * 2];
        decrypter.update(&chunk, &mut output)?;
        let mut xored_output = fixed_xor(&output[0..key.len()], &previous_chunk)?;
        if chunk_num == num_chunks - 1 {
            remove_padding(&mut xored_output, key.len() as u8);
            decrypted.extend_from_slice(&xored_output);
        } else {
            decrypted.extend_from_slice(&xored_output);
        }
        previous_chunk = chunk;
    }
    
    Ok(decrypted)
}

pub fn encrypt_cbc(key: &[u8], plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if iv.len() != key.len() {
        return Err(CliError("Key and IV length mismatch".into()).into());
    }
    let mut previous_cipher = iv;
    let mut encrypted: Vec<u8> = vec![];
    let cipher = Cipher::aes_128_ecb();
    for (idx, chunk) in plaintext.chunks(key.len()).enumerate() {
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
        let mut output = vec![0; key.len() * 2];
        let padding = key.len() - chunk.len();
        let xored_chunk = if padding > 0 {
            let padded_chunk = pad(chunk, key.len());
            fixed_xor(&padded_chunk, &previous_cipher)?
        } else {
            fixed_xor(chunk, &previous_cipher)?
        };
        encrypter.update(&xored_chunk, &mut output)?;
        encrypted.extend_from_slice(&output[0..key.len()]);
        let start = idx * key.len();
        previous_cipher = &encrypted[start..start + key.len()];
    }
    Ok(encrypted)
}

pub fn generate_random_bytes(length: usize, rng: &mut rand::rngs::ThreadRng) -> Vec<u8> {
    let mut random = vec![0; length];
    for i in 0..length {
        random[i] = rng.gen::<u8>();
    }
    random
}

pub enum EncryptedText {
    Cbc(Vec<u8>),
    Ecb(Vec<u8>)
}

impl EncryptedText {
    pub fn is_cbc(&self) -> bool {
        match *self {
            EncryptedText::Cbc(_) => true,
            _ => false,
        }
    }
    pub fn is_ecb(&self) -> bool {
        !self.is_cbc()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserProfile {
    email: String,
    uid: usize,
    role: String
}

impl UserProfile {
    pub fn profile_for(email: &str) -> Self {
        UserProfile {
            email: UserProfile::sanitize_email(email),
            uid: 10,
            role: "user".to_string()
        }
    }

    fn serialize(&self) -> Vec<u8> {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role).as_bytes().to_vec()
    }

    fn deserialize(input: &str) -> Result<Self, Box<dyn Error>> {
        let parts: Vec<&str> = input.split('&').collect();
        if parts.len() != 3 {
            return Err(CliError("invalid data".into()).into());
        }

        if !parts[0].contains("email=") || !parts[1].contains("uid=") || !parts[2].contains("role=") {
            return Err(CliError("invalid data".into()).into());
        }

        let email = parts[0].replace("email=", "");
        let uid = parts[1].replace("uid=", "").parse()?;
        let role = parts[2].replace("role=", "");

        Ok(Self {
            email,
            uid,
            role
        })
    }

    fn sanitize_email(email: &str) -> String {
        email.chars().filter(|ch| *ch != '&' && *ch != '=').collect()
    }

    fn get_key() -> Result<Vec<u8>, Box<dyn Error>> {
        match std::fs::read("profile_key.txt") {
            Ok(k) => Ok(k),
            Err(e) => {
                let mut rng = rand::thread_rng();
                let k = generate_random_bytes(16, &mut rng);
                std::fs::write("profile_key.txt", &k)?;
                Ok(k)
            }
        }
    }

    pub fn encrypt(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let output = encrypt_ecb(&UserProfile::get_key()?, &self.serialize())?;
        Ok(output)
    }

    pub (crate) fn decrypt(input: &[u8]) -> Result<Self, Box<dyn Error>> {
        let decrypted = decrypt_ecb(&UserProfile::get_key()?, input)?;
        println!("input = {:?}", input);
        println!("decrypted = {:?}", decrypted);
        UserProfile::deserialize(std::str::from_utf8(&decrypted)?)
    }
}

pub struct Oracle {
    key: Vec<u8>,
    input: Vec<u8>,
}

impl Oracle {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let key = match std::fs::read("key.txt") {
            Ok(k) => k,
            Err(_) => {
                let mut rng = rand::thread_rng();
                let k = generate_random_bytes(16, &mut rng);
                std::fs::write("key.txt", &k)?;
                k
            }
        };
        let input: String = std::fs::read_to_string("12.txt")
            .unwrap()
            .replace('\n', "");
        let to_crack = base64::base64_to_bytes(&input).expect("should decode");
        Ok(Self {
            key, input: to_crack
        })
    }

    pub fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut bytes = bytes.to_vec();
        bytes.extend_from_slice(&self.input);
        encrypt_ecb(&self.key, &bytes)
    }
}

/// Given a block size, some pad, and an oracle, create a lookup that will
/// match encrypted byte slices against bytes
fn create_lookup(pad_bytes: &[u8], block_size: usize, oracle: &Oracle) -> Result<HashMap<Vec<u8>, u8>, Box<dyn Error>> {
    let mut map: HashMap<Vec<u8>, u8> = HashMap::with_capacity(256);
    for byte in 0u8..255 {
        let mut padded_input = pad_bytes.to_vec();
        padded_input.push(byte);
        let encrypted = oracle.encrypt(&padded_input)?;
        let first_block = encrypted[0..block_size].to_vec();
        map.insert(first_block, byte);
    }
    Ok(map)
}

pub fn decrypt_block(block_num: usize, block_size: usize, oracle: &Oracle, pad: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    // bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    // block size = 3
    // append block size minus 1
    // bytes = [A, A, 1 | 2, 3, 4 | 5, 6, 7 | 8, 9, PAD]
    // decrypt byte 1 = D1
    // pad with 1 'A' and construct lookup table for A + D1 + ??
    // bytes = [A, D1, 2 | 3, 4, 5 | 6, 7, 8 | 9, PAD, PAD]
    // decrypt byte 2 = D2
    // no padding, construct lookup table D1 + D2 + ??
    // bytes = [D1, D2, 3 | 4, 5, 6 | 7, 8, 9]
    // decrypt byte 3 = D3
    // pad with [A, A] construct lookup table D2 + D3 = ??
    // bytes = [A, A, D1 | D2, D3, 4 | 5, 6, 7 | 8, 9, PAD]
    // decrypt byte 4 = D4
    // pad with A construct lookup table D3 + D4 = ??
    // bytes = [A, D1, D2 | D3, D4, 5 | 6, 7, 8 | 9, PAD, PAD]
    // decrypt byte 5 = D5
    let mut pad: Vec<u8> = pad.to_vec();

    let mut plaintext: Vec<u8> = vec![];
    let max_pad_size = block_size - 1;

    for i in 0..block_size {
        let pad_size = max_pad_size - i;
        // what we send to the oracle to push bytes over
        let encryption_pad: Vec<u8> = (0..pad_size)
            .map(|_| 'A' as u8)
            .collect();

        let lookup = create_lookup(&pad, block_size, &oracle).expect("should create the oracle");
        let encrypted = oracle.encrypt(&encryption_pad).expect("should encrypt the text");

        let start = block_num * block_size;
        let end = std::cmp::min(start + block_size, encrypted.len()-1);
        if start >= encrypted.len() || end >= encrypted.len() {
            println!("start={} >= len={} || end={} >= len={}", start, encrypted.len(), end, encrypted.len());
            return Err(plaintext);
        }
        let first_block = encrypted[start..end].to_vec();
        let first_char = lookup.get(&first_block);
        if let Some(ch) = first_char {
            plaintext.push(*ch);
            pad.push(*ch);
            pad.remove(0);
        } else {
            println!("nothing found at {} for block {}", i, block_num);
            return Err(plaintext);
        }
    }

    return Ok(plaintext)
}

pub fn discover_blocksize(oracle: &Oracle) -> Result<usize, Box<dyn std::error::Error>> {
    let encrypted_len = oracle.encrypt("".as_bytes())?.len();
    for idx in 1..32 {
        let guess: Vec<u8> = (0..idx).map(|_i| 'a' as u8).collect();
        let encrypted = oracle.encrypt(&guess)?;
        let diff = encrypted.len() - encrypted_len;
        if diff > 0 {
            return Ok(diff);
        }
    }
    Err(CliError("couldn't guess keysize :(".into()).into())
}

pub fn is_ecb(key_size: usize, ciphertext: &[u8]) -> bool {
    let mut identical_chunks = 0;
    for (idx, chunk) in ciphertext.chunks(key_size).enumerate() {
        for (idx2, chunk2) in ciphertext.chunks(key_size).enumerate() {
            if idx == idx2 {
                continue;
            }
            if chunk == chunk2 {
                identical_chunks += 1;
            }
        }
    }
    identical_chunks > 0
}

pub fn encryption_oracle(text: &[u8]) -> Result<EncryptedText, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let prepend_length = rng.gen_range(5..10);
    let append_length = rng.gen_range(5..10);
    let key = generate_random_bytes(16, &mut rng);
    let prepend_text = generate_random_bytes(prepend_length, &mut rng);
    let append_text = generate_random_bytes(append_length, &mut rng);
    let mut input: Vec<u8> = Vec::with_capacity(text.len() + prepend_text.len() + append_text.len());
    input.extend_from_slice(&prepend_text);
    input.extend_from_slice(&text);
    input.extend_from_slice(&append_text);

    if rng.gen_bool(0.5) {
        let encrypted = encrypt_ecb(&key, &input)?;
        Ok(EncryptedText::Ecb(encrypted))
    } else {
        let iv = generate_random_bytes(16, &mut rng);
        let encrypted = encrypt_cbc(&key, &input, &iv)?;
        Ok(EncryptedText::Cbc(encrypted))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_remove_padding() {
        let mut padded = pad("hey".as_bytes(), 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(padded[3..], [7, 7, 7, 7, 7, 7, 7]);
        remove_padding(&mut padded, 10); 
        assert_eq!(padded.len(), 3);
    }

    #[test]
    fn test_cbc() {
        let plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let key = "YELLOW SUBMARINE";
        let iv = "0123456789abcdef";
        let encrypted = encrypt_cbc(key.as_bytes(), plaintext.as_bytes(), iv.as_bytes()).expect("to encrypt");
        assert_eq!(encrypted.len(), plaintext.len());
        let decrypted = decrypt_cbc(key.as_bytes(), &encrypted, iv.as_bytes()).expect("to decrypt");
        assert_eq!(decrypted, plaintext.as_bytes(), "Original {:?}\n Decrypted {:?}", plaintext.as_bytes(), decrypted);
    }

    #[test]
    fn test_cbc_padding() {
        let plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let key = "YELLOW SUBMARINE";
        let iv = "0123456789abcdef";
        let encrypted = encrypt_cbc(key.as_bytes(), plaintext.as_bytes(), iv.as_bytes()).expect("to encrypt");
        assert_eq!(encrypted.len(), 32);
        let decrypted = decrypt_cbc(key.as_bytes(), &encrypted, iv.as_bytes()).expect("to decrypt");
        assert_eq!(decrypted, plaintext.as_bytes(), "Original {:?}\n Decrypted {:?}", plaintext.as_bytes(), decrypted);
    }

    #[test]
    fn test_ecb_encryption() {
        let plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let encrypted = encrypt_ecb("YELLOW SUBMARINE".as_bytes(), plaintext.as_bytes()).expect("should encrypt");
        let decrypted = decrypt_ecb("YELLOW SUBMARINE".as_bytes(), &encrypted).expect("should decrypt");
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_user_profile() {
        let profile = UserProfile::profile_for("peter@peter.com");
        let encrypted = profile.encrypt().expect("should encrypt");
        let decrypted = UserProfile::decrypt(&encrypted).expect("should deserialize");
        assert_eq!(profile, decrypted);
    }
}
