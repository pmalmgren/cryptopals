use crate::error::CliError;

pub fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>, CliError> {
    if lhs.len() != rhs.len() {
        return Err(CliError("Length of two buffers must match.".to_string()));
    }

    Ok(lhs
        .into_iter()
        .zip(rhs.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect())
}

pub fn single_xor(lhs: &[u8], rhs: u8) -> Vec<u8> {
    lhs
        .into_iter()
        .map(|b| b ^ rhs)
        .collect()
}

pub fn repeating_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    for chunk in input.chunks(key.len()) {
        output.extend(fixed_xor(chunk, &key[..chunk.len()]).unwrap());
    }

    output
}
