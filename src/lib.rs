use blake2b_simd::blake2b;
use ckb_merkle_mountain_range::{util::MemStore, Merge, Result as CkbResult, MMR};
use hex;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsError;

#[wasm_bindgen]
#[derive(Debug)]
pub struct MMRResult {
    root: String,
    proof: String,
}

impl std::fmt::Display for MMRResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Root: {}\nProof: {}", self.root, self.proof)
    }
}

impl std::error::Error for MMRResult {}

#[wasm_bindgen]
// Define a custom merge function (Blake2b hashing)
#[derive(Debug)]
struct Blake2bMerge;
impl Merge for Blake2bMerge {
    type Item = [u8; 32];
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> CkbResult<Self::Item> {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(lhs);
        input.extend_from_slice(rhs);
        let hash = blake2b(&input);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash.as_bytes()[..32]);
        Ok(result)
    }
}

fn is_leaf(pos: u64) -> bool {
    pos & (pos + 1) == 0
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn bytes_to_hex_proof(bytes: &[[u8; 32]]) -> String {
    let mut proof_items = Vec::new();
    for item in bytes {
        proof_items.push(bytes_to_hex(item));
    }
    proof_items.join(",")
}

#[wasm_bindgen]
pub fn generate_root(items_len: u64, target_pos: u64) -> Result<MMRResult, JsError> {
    // Initialize MMR
    let store = MemStore::<[u8; 32]>::default();
    let mut mmr = MMR::<[u8; 32], Blake2bMerge, &MemStore<[u8; 32]>>::new(0, &store);
    let mut leaf_data = HashMap::new();

    // Insert leaves
    for i in 0..items_len {
        let mut tx = [0u8; 32];
        tx[0] = i as u8; // Use the index as the first byte
        let pos = mmr.push(tx).map_err(|e| JsError::new(&e.to_string()))?;
        leaf_data.insert(pos, tx);

        let root = mmr.get_root().map_err(|e| JsError::new(&e.to_string()))?;

        // Only generate and verify proof for leaf nodes
        if is_leaf(pos) && pos == target_pos {
            // Generate proof for the leaf node
            let proof = mmr
                .gen_proof(vec![pos])
                .map_err(|e| JsError::new(&e.to_string()))?;

            let leaf = leaf_data.get(&pos).unwrap();

            let is_valid = proof
                .verify(root.clone(), vec![(pos, *leaf)])
                .map_err(|e| JsError::new(&e.to_string()))?;
            println!(
                "Proof for leaf node {} (position {}) valid: {}",
                i, pos, is_valid
            );

            println!(
                "Leaf data for node {} (position {}) (hex): {}",
                i,
                pos,
                bytes_to_hex(leaf)
            );

            return Ok(MMRResult {
                root: bytes_to_hex(&root),
                proof: bytes_to_hex_proof(&proof.proof_items()),
            });
        }
    }
    Err(JsError::new("Node proofs not supported"))
}
