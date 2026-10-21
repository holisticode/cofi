use sha2::{Digest, Sha256};

/// Build a Merkle root from sorted key-value pairs.
///
/// Entries are sorted by key for determinism, then hashed pairwise bottom-up.
/// Odd layers promote the unpaired node (duplicated for hashing).
/// An empty set yields the zero hash.
pub fn merkle_root(entries: &mut [(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut level: Vec<[u8; 32]> = entries.iter().map(|(k, v)| leaf_hash(k, v)).collect();

    if level.is_empty() {
        return [0u8; 32];
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(&pair[0]);
            if pair.len() == 2 {
                h.update(&pair[1]);
            } else {
                h.update(&pair[0]);
            }
            next.push(h.finalize().into());
        }
        level = next;
    }

    level[0]
}

fn leaf_hash(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(value);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_zero_hash() {
        assert_eq!(merkle_root(&mut []), [0u8; 32]);
    }

    #[test]
    fn single_entry_is_leaf_hash() {
        let expected = leaf_hash(b"key", b"value");
        assert_eq!(merkle_root(&mut [(b"key".to_vec(), b"value".to_vec())]), expected);
    }

    #[test]
    fn deterministic_regardless_of_input_order() {
        let mut a = vec![
            (b"b".to_vec(), b"2".to_vec()),
            (b"a".to_vec(), b"1".to_vec()),
            (b"c".to_vec(), b"3".to_vec()),
        ];
        let mut b = vec![
            (b"c".to_vec(), b"3".to_vec()),
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
        ];
        assert_eq!(merkle_root(&mut a), merkle_root(&mut b));
    }

    #[test]
    fn different_values_produce_different_roots() {
        let r1 = merkle_root(&mut [(b"k".to_vec(), b"v1".to_vec())]);
        let r2 = merkle_root(&mut [(b"k".to_vec(), b"v2".to_vec())]);
        assert_ne!(r1, r2);
    }
}
