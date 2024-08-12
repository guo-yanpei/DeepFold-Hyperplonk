use std::fmt::Debug;

use arithmetic::field::Field;
use util::fiat_shamir::{Proof, Transcript};

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
    fn open(
        pp: &Self::Param,
        prover_point: Vec<(&Self, Vec<Vec<Vec<F>>>)>,
        transcript: &mut Transcript,
    );
}

pub trait PolyCommitVerifier<F: Field>: Clone {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, commit: Self::Commitment) -> Self;
    fn verify(
        pp: &Self::Param,
        commit_point: Vec<(&Self, Vec<Vec<Vec<F>>>)>,
        evals: Vec<Vec<Vec<F>>>,
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
        poly::MultiLinearPoly,
    };
    use util::fiat_shamir::Transcript;

    use crate::{
        shuffle::{RawCommitment, ShufflePcProver, ShufflePcVerifier},
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
        let prover = ShufflePcProver::new(&(), &[poly_evals]);
        let commitment = prover.commit();
        let mut buffer = vec![0u8; RawCommitment::<Goldilocks64Ext>::size(12, 1)];
        commitment.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, RawCommitment::<Goldilocks64Ext>::size(12, 1));
        transcript.append_f(eval);
        ShufflePcProver::open(
            &(),
            vec![(&prover, vec![vec![point.clone()]])],
            &mut transcript,
        );
        let mut proof = transcript.proof;

        let commitment = RawCommitment::deserialize_from(&mut proof, 12, 1);
        let mut transcript = Transcript::new();
        let mut buffer = vec![0u8; RawCommitment::<Goldilocks64Ext>::size(12, 1)];
        commitment.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, RawCommitment::<Goldilocks64Ext>::size(12, 1));
        let verifier = ShufflePcVerifier::new(&(), commitment);
        let eval = vec![vec![vec![proof.get_next_and_step()]]];
        transcript.append_f(eval[0][0][0]);
        assert!(ShufflePcVerifier::verify(
            &(),
            vec![(&verifier, vec![vec![point]])],
            eval,
            &mut transcript,
            &mut proof
        ));
    }
}
