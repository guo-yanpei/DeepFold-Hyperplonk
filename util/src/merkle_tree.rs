use rs_merkle::{Hasher, MerkleProof, MerkleTree};

#[derive(Debug, Clone)]
pub struct Blake3Algorithm {}

impl Hasher for Blake3Algorithm {
    type Hash = [u8; HASH_SIZE];

    fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
        blake3::hash(data).into()
    }
}

pub const HASH_SIZE: usize = 32;
#[derive(Clone)]
pub struct MerkleTreeProver {
    pub merkle_tree: MerkleTree<Blake3Algorithm>,
    leave_num: usize,
}

#[derive(Debug, Clone)]
pub struct MerkleTreeVerifier {
    pub merkle_root: [u8; HASH_SIZE],
    pub leave_number: usize,
}

impl MerkleTreeProver {
    // leaf number should be 2^n
    pub fn new(leaf_values: Vec<Vec<u8>>) -> Self {
        let leaves = leaf_values
            .iter()
            .map(|x| Blake3Algorithm::hash(x))
            .collect::<Vec<_>>();
        let merkle_tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
        Self {
            merkle_tree,
            leave_num: leaf_values.len(),
        }
    }

    pub fn leave_num(&self) -> usize {
        self.leave_num
    }

    pub fn commit(&self) -> [u8; HASH_SIZE] {
        self.merkle_tree.root().unwrap()
    }

    pub fn open(&self, leaf_indices: &Vec<usize>) -> Vec<u8> {
        self.merkle_tree.proof(leaf_indices).to_bytes()
    }
}

impl MerkleTreeVerifier {
    pub fn new(leave_number: usize, merkle_root: [u8; HASH_SIZE]) -> Self {
        Self {
            leave_number,
            merkle_root,
        }
    }

    fn difference<T: Clone + PartialEq>(a: &[T], b: &[T]) -> Vec<T> {
        a.iter().filter(|&x| !b.contains(x)).cloned().collect()
    }

    pub fn proof_length(&self, indices: &Vec<usize>) -> usize {
        let mut current_layer_indices = indices.to_vec();
        let mut res = 0;
        for _ in 0..self.leave_number.ilog2() {
            let siblings = current_layer_indices
                .iter()
                .cloned()
                .map(|index| index ^ 1)
                .collect::<Vec<_>>();
            let help_indices = Self::difference(&siblings, &current_layer_indices);
            res += help_indices.len();
            current_layer_indices.iter_mut().for_each(|x| *x >>= 1);
            current_layer_indices.dedup();
        }
        res * HASH_SIZE
    }

    pub fn verify(
        &self,
        proof_bytes: Vec<u8>,
        indices: &Vec<usize>,
        leaves: &Vec<Vec<u8>>,
    ) -> bool {
        let proof = MerkleProof::<Blake3Algorithm>::try_from(proof_bytes).unwrap();
        let leaves_to_prove: Vec<[u8; HASH_SIZE]> =
            leaves.iter().map(|x| Blake3Algorithm::hash(x)).collect();
        proof.verify(
            self.merkle_root,
            indices,
            &leaves_to_prove,
            self.leave_number,
        )
    }
}

pub struct MerkleRoot;
impl MerkleRoot {
    pub fn get_root(
        proof_bytes: Vec<u8>,
        index: usize,
        leaf: Vec<u8>,
        total_leaves_count: usize,
    ) -> [u8; HASH_SIZE] {
        let proof = MerkleProof::<Blake3Algorithm>::try_from(proof_bytes).unwrap();
        let leaf_hashes = vec![Blake3Algorithm::hash(&leaf)];
        proof
            .root(&vec![index], &leaf_hashes, total_leaves_count)
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use arithmetic::field::{goldilocks64::Goldilocks64, Field};

    use super::*;

    fn as_bytes_vec<F: Field>(v: &[F]) -> Vec<u8> {
        let mut res = vec![0u8; F::SIZE * v.len()];
        let mut cnt = 0;
        for i in v {
            i.serialize_into(&mut res[cnt..]);
            cnt += F::SIZE;
        }
        res
    }

    #[test]
    fn commit_and_open() {
        let leaf_values = vec![
            as_bytes_vec(&[Goldilocks64::from(1u32), Goldilocks64::from(2u32)]),
            as_bytes_vec(&[Goldilocks64::from(3u32), Goldilocks64::from(4u32)]),
            as_bytes_vec(&[Goldilocks64::from(5u32), Goldilocks64::from(6u32)]),
            as_bytes_vec(&[Goldilocks64::from(7u32), Goldilocks64::from(8u32)]),
            as_bytes_vec(&[Goldilocks64::from(9u32), Goldilocks64::from(10u32)]),
            as_bytes_vec(&[Goldilocks64::from(11u32), Goldilocks64::from(12u32)]),
            as_bytes_vec(&[Goldilocks64::from(13u32), Goldilocks64::from(14u32)]),
            as_bytes_vec(&[Goldilocks64::from(15u32), Goldilocks64::from(16u32)]),
        ];
        let leave_number = leaf_values.len();
        let prover = MerkleTreeProver::new(leaf_values);
        let root = prover.commit();
        let verifier = MerkleTreeVerifier::new(leave_number, root);
        let leaf_indices = vec![2, 3, 4];
        let proof_bytes = prover.open(&leaf_indices);
        assert_eq!(proof_bytes.len(), verifier.proof_length(&leaf_indices));
        let open_values = vec![
            as_bytes_vec(&[Goldilocks64::from(5u32), Goldilocks64::from(6u32)]),
            as_bytes_vec(&[Goldilocks64::from(7u32), Goldilocks64::from(8u32)]),
            as_bytes_vec(&[Goldilocks64::from(9u32), Goldilocks64::from(10u32)]),
        ];
        assert!(verifier.verify(proof_bytes, &leaf_indices, &open_values));
    }
}
