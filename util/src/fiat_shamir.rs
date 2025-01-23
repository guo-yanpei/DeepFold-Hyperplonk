use std::mem::size_of;

use arithmetic::field::Field;
use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct Proof {
    idx: usize,
    pub bytes: Vec<u8>,
}

impl Proof {
    #[inline(always)]
    pub fn append_u8_slice(&mut self, buffer: &[u8], size: usize) {
        self.bytes.extend_from_slice(&buffer[..size]);
    }

    #[inline(always)]
    fn step(&mut self, size: usize) {
        self.idx += size;
    }

    #[inline(always)]
    pub fn get_next_and_step<F: Field>(&mut self) -> F {
        let ret = F::deserialize_from(&self.bytes[self.idx..(self.idx + F::SIZE)]);
        self.step(F::SIZE);
        ret
    }

    pub fn get_next_hash(&mut self) -> [u8; HASH_SIZE] {
        let ret = self.bytes[self.idx..(self.idx + HASH_SIZE)]
            .try_into()
            .unwrap();
        self.step(HASH_SIZE);
        ret
    }

    pub fn get_next_slice(&mut self, len: usize) -> Vec<u8> {
        let ret = self.bytes[self.idx..(self.idx + len)].to_vec();
        self.step(len);
        ret
    }
}

#[derive(Debug, Clone, Default)]
pub struct SHA256hasher;

impl SHA256hasher {
    pub fn hash(&self, output: &mut [u8], input: &[u8], input_len: usize) {
        let hashed = Sha256::digest(&input[..input_len]);
        output.copy_from_slice(&hashed[..]);
    }
    pub fn hash_inplace(&self, buffer: &mut [u8], input_len: usize) {
        let hashed = Sha256::digest(&buffer[..input_len]);
        buffer.copy_from_slice(&hashed[..]);
    }
}

pub struct Transcript {
    pub hasher: SHA256hasher,
    hash_start_idx: usize,
    digest: [u8; Self::DIGEST_SIZE],
    pub proof: Proof,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    pub const DIGEST_SIZE: usize = 32;

    fn hash_to_digest(&mut self) {
        let hash_end_idx = self.proof.bytes.len();
        if hash_end_idx > self.hash_start_idx {
            self.hasher.hash(
                &mut self.digest,
                &self.proof.bytes[self.hash_start_idx..],
                hash_end_idx - self.hash_start_idx,
            );
            self.hash_start_idx = hash_end_idx;
        } else {
            self.hasher
                .hash_inplace(&mut self.digest, Self::DIGEST_SIZE)
        }
    }

    #[inline]
    pub fn new() -> Self {
        Transcript {
            hasher: SHA256hasher,
            hash_start_idx: 0,
            digest: [0u8; Self::DIGEST_SIZE],
            proof: Proof::default(),
        }
    }

    pub fn append_f<F: Field>(&mut self, f: F) {
        let cur_size = self.proof.bytes.len();
        self.proof.bytes.resize(cur_size + F::SIZE, 0);
        f.serialize_into(&mut self.proof.bytes[cur_size..]);
    }

    pub fn append_u8_slice(&mut self, buffer: &[u8], size: usize) {
        self.proof.append_u8_slice(buffer, size);
    }

    pub fn challenge_f<F: Field>(&mut self) -> F {
        self.hash_to_digest();
        assert!(F::SIZE <= Self::DIGEST_SIZE);
        F::from_uniform_bytes(&self.digest)
    }

    pub fn challenge_usizes(&mut self, num: usize) -> Vec<usize> {
        (0..num)
            .map(|_| {
                self.hash_to_digest();
                usize::from_be_bytes(self.digest[0..size_of::<usize>()].try_into().unwrap())
            })
            .collect()
    }
}
