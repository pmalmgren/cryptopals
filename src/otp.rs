use radix_trie::Trie;
use std::fs::File;
use std::io::BufRead;
use std::collections::{HashMap, HashSet, BinaryHeap};

use crate::hex;
use crate::error::CliError;
use crate::xor;

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

pub fn one_time_pad_encrypt(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 2 {
        return Err(CliError("Give me 2 strings.".to_string()).into());
    }

    let message1 = hex::hex_str_to_bytes(&args[0])?;
    let message2 = hex::hex_str_to_bytes(&args[1])?;
    let xored = xor::fixed_xor(&message1, &message2)?;

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
