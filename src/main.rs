use std::env::args;
use std::path::Path;
use radix_trie::Trie;
use std::fs::File;
use std::io::BufRead;
use std::collections::{HashMap, HashSet, BinaryHeap};

mod base64;
mod hex;
mod distance;

#[derive(Debug)]
struct CliError(String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CliError {}

fn build_trie<'a>(words: &'a[String]) -> Trie<&'a str, u32> {
    let mut trie: Trie<&str, u32> = Trie::new();
    for j in 0..words.len() {
        let word = &words[j];
        for i in 1..word.len()+1 {
            let substr = &word[0..i];
            let val = trie.get_mut(substr);
            match val {
                None => {
                    trie.insert(substr, 1);
                }
                Some(v) => {
                    *v += 1; 
                }
            };
        }
    }

    trie
}

fn one_time_pad_encrypt(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 2 {
        return Err(CliError("Give me 2 strings.".to_string()).into());
    }

    let message1 = hex::hex_str_to_bytes(&args[0])?;
    let message2 = hex::hex_str_to_bytes(&args[1])?;
    let xored = fixed_xor(&message1, &message2)?;

    let file = File::open("elevenletters.txt").unwrap();
    let reader = std::io::BufReader::new(file).lines();
    let mut all_words: Vec<String> = Vec::with_capacity(45000);
    for line in reader {
        let line = line.unwrap();
        all_words.push(line.to_string());
    }

    let trie = build_trie(&all_words);

    // Algorithm:
    // for the current xor'd byte, calculate the possible combinations of letters
    // ex. 12, ('c', 'b'), ('e', 'a')
    // for the next xor'd byte, calculate the possible combinations of letters
    // ex. 11, ('a', 'x'), ('a', 'e')
    // for all the combinations of letters, select ones which are prefixes of
    // valid words. ex. 

    println!("{}", &args[0]);
    println!("XOR\n{}", &args[1]);
    println!("=\n{}", hex::bytes_to_hex_str(&xored));

    let alphabet = vec!['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '-'];
    let mut alphabet_xor: HashMap<u8, HashSet<(String, String)>> = HashMap::new();

    for byte in &xored {
        alphabet_xor.insert(*byte, HashSet::new());
    }
    for ch in alphabet.iter() {
        for ch1 in alphabet.iter() {
            let val = (*ch as u8) ^ (*ch1 as u8);
            if let Some(ref mut set) = alphabet_xor.get_mut(&val) {
                let tup = if ch > ch1 {
                    (ch.to_string(), ch1.to_string())
                } else {
                    (ch1.to_string(), ch.to_string())
                };
                set.insert(tup);
            }
        }
    }

    let mut acc: BinaryHeap<AccItem> = BinaryHeap::new();
    check_next("", "", &alphabet_xor, &xored[0], &trie, &mut acc);

    for byte in &xored[1..] {
        let mut acc_next: BinaryHeap<AccItem> = BinaryHeap::new();
        while let Some(item) = acc.pop() {
            let AccItem { lhs, rhs, .. } = item;
            check_next(&lhs, &rhs, &alphabet_xor, byte, &trie, &mut acc_next);
        }
        println!("{:?}", acc_next);
        acc = acc_next;
    }

    Ok(())
}

#[derive(Debug, Clone, Eq)]
struct AccItem {
    score: u32,
    lhs: String,
    rhs: String,
}

impl PartialEq for AccItem {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }

    fn ne(&self, other: &Self) -> bool {
        self.score != other.score
    }
}

impl PartialOrd for AccItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.score.partial_cmp(&other.score)
    }
}

impl Ord for AccItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score.cmp(&other.score)
    }
}

/*
 *
 * 27: {('u', 'n'), ('r', 'i'), ('t', 'o'), ('p', 'k'), ('w', 'l'), ('q', 'j'), ('x', 'c'), ('z', 'a'), ('y', 'b'), ('s', 'h'), ('v', 'm')}
 * 12: {('m', 'a'), ('k', 'g'), ('x', 't'), ('j', 'f'), ('i', 'e'), ('n', 'b'), ('o', 'c'), ('h', 'd'), ('z', 'v'), ('y', 'u')}
 * 20: {('s', 'g'), ('v', 'b'), ('x', 'l'), ('y', 'm'), ('r', 'f'), ('p', 'd'), ('u', 'a'), ('w', 'c'), ('q', 'e'), ('z', 'n')}
 * 26: {('v', 'l'), ('q', 'k'), ('y', 'c'), ('r', 'h'), ('s', 'i'), ('u', 'o'), ('t', 'n'), ('p', 'j'), ('w', 'm'), ('x', 'b')} 
 * 7: {('f', 'a'), ('u', 'r'), ('d', 'c'), ('m', 'j'), ('v', 'q'), ('t', 's'), ('o', 'h'), ('e', 'b'), ('l', 'k'), ('n', 'i'), ('w', 'p')}
 * 5: {('g', 'b'), ('m', 'h'), ('u', 'p'), ('d', 'a'), ('l', 'i'), ('n', 'k'), ('t', 'q'), ('v', 's'), ('f', 'c'), ('w', 'r'), ('o', 'j')}
 * 1: {('q', 'p'), ('w', 'v'), ('m', 'l'), ('i', 'h'), ('g', 'f'), ('o', 'n'), ('u', 't'), ('y', 'x'), ('e', 'd'), ('c', 'b'), ('k', 'j'), ('s', 'r')}
 * 8: {('n', 'f'), ('x', 'p'), ('i', 'a'), ('l', 'd'), ('y', 'q'), ('j', 'b'), ('k', 'c'), ('m', 'e'), ('o', 'g'), ('z', 'r')}
 * 23: {('u', 'b'), ('r', 'e'), ('x', 'o'), ('q', 'f'), ('s', 'd'), ('v', 'a'), ('p', 'g'), ('z', 'm'), ('y', 'n'), ('t', 'c')}
 * 11: {('l', 'g'), ('j', 'a'), ('m', 'f'), ('o', 'd'), ('z', 'q'), ('i', 'b'), ('y', 'r'), ('h', 'c'), ('x', 's'), ('n', 'e')}}
 * 
 * 12 7 20
 * Iter 0
 * 
 * heap: {("m", "a"), ("k", "g"), ('x', 't'), ('j', 'f'), ('i', 'e'), ('n', 'b'), ('o', 'c'), ('h', 'd'), ('z', 'v'), ('y', 'u')}
 *
 *   ("o", "c")
 * x ('f', 'a')
 * = ("of", "ca"), ("oa", "cf")
 * = [some score], [0]
 *   ("o", "c")
 * x ('u', 'r')
 * = ("ou", "cr"), ("or", "cu")
 *   [some score], [some score]
 * "
 */

fn check_next(lhs: &str, rhs: &str, alphabet_xor: &HashMap<u8, HashSet<(String, String)>>, xored: &u8, trie: &Trie<&str, u32>, acc: &mut BinaryHeap<AccItem>) {
    let possibilities = alphabet_xor.get(&xored).unwrap();
    for (ch, ch1) in possibilities {
        let prefix_lhs1 = [lhs, ch].concat();
        let prefix_lhs2 = [lhs, ch1].concat();

        let score_lhs1 = trie.get(prefix_lhs1.as_str()).unwrap_or_else(|| &0u32);
        let score_lhs2 = trie.get(prefix_lhs2.as_str()).unwrap_or_else(|| &0u32);

        if *score_lhs1 > 0 {
            let prefix_rhs1 = [rhs, ch1].concat();
            let score_rhs1 = trie.get(prefix_rhs1.as_str()).unwrap_or_else(|| &0);
            if *score_rhs1 > 0 {
                acc.push(AccItem{ lhs: prefix_lhs1, rhs: prefix_rhs1, score: score_rhs1 + score_lhs1 });
            }
        }

        if *score_lhs2 > 0 {
            let prefix_rhs2 = [rhs, ch].concat();
            let score_rhs2 = trie.get(prefix_rhs2.as_str()).unwrap_or_else(|| &0);
            if *score_rhs2 > 0 {
                acc.push(AccItem{ lhs: prefix_lhs2, rhs: prefix_rhs2, score: score_rhs2 + score_lhs2 });
            }
        }
    }
}

fn challenge1(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() > 1 {
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        println!("{}", base64::slice_to_base64(&decoded));
    }

    Ok(())
}

fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>, CliError> {
    if lhs.len() != rhs.len() {
        return Err(CliError("Length of two buffers must match.".to_string()));
    }

    Ok(lhs
        .into_iter()
        .zip(rhs.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect())
}

fn single_xor(lhs: &[u8], rhs: u8) -> Vec<u8> {
    lhs
        .into_iter()
        .map(|b| b ^ rhs)
        .collect()
}

fn challenge2(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() > 2 {
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        let decoded2 = hex::hex_str_to_bytes(&args[2])?;
        let xord = fixed_xor(&decoded, &decoded2)?;
        println!("{}", hex::bytes_to_hex_str(&xord));
    }

    Ok(())
}

fn challenge4() -> Result<(), Box<dyn std::error::Error>> {
    let challenge_file_contents = std::fs::read_to_string(Path::new("4.txt"))?;

    let mut biggest = (0.0, 0);
    let lines: Vec<String> = challenge_file_contents.split('\n').map(String::from).collect();

    for (index, line) in lines.iter().enumerate() {
        let decoded = hex::hex_str_to_bytes(&line)?;
        let decoded_str = std::str::from_utf8(&decoded).expect(format!("couldn't decode utf8 for {} - {:?}", line, decoded).as_str());
        let distribution = distance::CharacterDistribution::from_text(decoded_str); 
        
        let distance = distance::ENGLISH_ALPHABET.compare(&distribution);
        if distance > biggest.0 {
            biggest = (distance, index);
        }
    }

    println!("xor encoded line = {}", lines[biggest.1]);
    
    Ok(())
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
    'Y', 'Z',
];

fn challenge3(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() > 1 {
        let english = &distance::ENGLISH_ALPHABET;
        let decoded = hex::hex_str_to_bytes(&args[1])?;
        let mut smallest = ('-', 1.0);
        for ch in ASCII_LOWER.iter() {
            let decoded = single_xor(&decoded, *ch as u8);
            let decoded_str = std::str::from_utf8(&decoded)?;
            let decoded_distribution = distance::CharacterDistribution::from_text(decoded_str);
            let distance = english.compare(&decoded_distribution);
            if distance < smallest.1 {
                smallest = (*ch, distance);
            }
        }
        println!("Smallest Euclidean distance letter {} = {}", smallest.0, smallest.1);
        let decoded = single_xor(&decoded, smallest.0 as u8);
        let decoded_str = std::str::from_utf8(&decoded)?;
        println!("Decoded = {}", decoded_str);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args: Vec<String> = args().collect();

    if args.len() <= 1 {
        eprintln!("Usage: [subcommand] [arguments]");
        return Err(CliError("Incorrect arguments".to_string()).into());
    }

    match args[1].as_ref() {
        "padproblem" => one_time_pad_encrypt(&args[2..]),
        "challenge1" => challenge1(&args[1..]),
        "challenge2" => challenge2(&args[1..]),
        "challenge3" => challenge3(&args[1..]),
        "challenge4" => challenge4(),
        cmd => {
            eprintln!("Unknown subcommand {}", cmd);
            return Err(CliError("Unknown command".to_string()).into());
        }
    }
}