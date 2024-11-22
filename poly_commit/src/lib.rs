use std::fmt::Debug;

use arithmetic::field::Field;
use util::fiat_shamir::{Proof, Transcript};

pub mod deepfold;
pub mod nil;
pub mod shuffle;
pub trait CommitmentSerde {
    fn size(nv: usize, np: usize) -> usize;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(proof: &mut Proof, var_num: usize, poly_num: usize) -> Self;
}

pub trait PolyCommitProver<F: Field>: Clone {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, poly: &[Vec<F::BaseField>]) -> Self;
    fn commit(&self) -> Self::Commitment;
    fn open(pp: &Self::Param, provers: Vec<&Self>, point: Vec<F>, transcript: &mut Transcript);
}

pub trait PolyCommitVerifier<F: Field>: Clone {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, commit: Self::Commitment, poly_num: usize) -> Self;
    fn verify(
        pp: &Self::Param,
        commits: Vec<&Self>,
        point: Vec<F>,
        evals: Vec<Vec<F>>,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool;
}

mod tests {
    use arithmetic::{
        field::{
            goldilocks64::{Goldilocks64, Goldilocks64Ext},
            Field,
        },
        mul_group::Radix2Group,
        poly::MultiLinearPoly,
    };
    use util::fiat_shamir::Transcript;

    use crate::{
        deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier, MerkleRoot},
        CommitmentSerde, PolyCommitProver, PolyCommitVerifier,
    };

    #[test]
    fn pc_commit_prove_verify() {
        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new();
        let poly_evals = (0..4096).map(|_| Goldilocks64::random(&mut rng)).collect();
        let point = (0..12)
            .map(|_| Goldilocks64Ext::random(&mut rng))
            .collect::<Vec<_>>();
        let eval = MultiLinearPoly::eval_multilinear(&poly_evals, &point);
        let mut mult_subgroups = vec![Radix2Group::<Goldilocks64>::new(15)];
        for i in 1..12 {
            mult_subgroups.push(mult_subgroups[i - 1].exp(2));
        }

        let pp = DeepFoldParam::<Goldilocks64Ext> {
            mult_subgroups,
            variable_num: 12,
            query_num: 30,
        };
        let prover = DeepFoldProver::new(&pp, &[poly_evals]);
        let commitment = prover.commit();
        let mut buffer = vec![0u8; MerkleRoot::size(12, 1)];
        commitment.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, MerkleRoot::size(12, 1));
        transcript.append_f(eval);
        DeepFoldProver::open(&pp, vec![&prover], point.clone(), &mut transcript);
        let mut proof = transcript.proof;

        let commitment = MerkleRoot::deserialize_from(&mut proof, 12, 1);
        let mut transcript = Transcript::new();
        let mut buffer = vec![0u8; MerkleRoot::size(12, 1)];
        commitment.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, MerkleRoot::size(12, 1));
        let verifier = DeepFoldVerifier::new(&pp, commitment, 1);
        let eval = vec![vec![proof.get_next_and_step()]];
        transcript.append_f(eval[0][0]);
        assert!(DeepFoldVerifier::verify(
            &pp,
            vec![&verifier],
            point,
            eval,
            &mut transcript,
            &mut proof
        ));
    }
}
