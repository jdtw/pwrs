const HEX: &[char; 16] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
];

fn hex_chars(b: u8) -> Vec<char> {
    vec![HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| hex_chars(b))
        .flat_map(|v| v.into_iter())
        .collect()
}
