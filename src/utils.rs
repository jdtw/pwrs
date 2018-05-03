const HEX: &[char; 16] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
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

pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl ToHex for Vec<u8> {
    fn to_hex(&self) -> String {
        self::to_hex(self)
    }
}

impl<'a> ToHex for &'a [u8] {
    fn to_hex(&self) -> String {
        to_hex(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex() {
        let bytes: Vec<u8> = vec![0, 1, 2, 3, 10, 15, 255];
        assert_eq!(bytes.to_hex(), "000102030a0fff");
    }
}
