use std::fmt::Debug;

use arithmetic::field::Field;
use util::fiat_shamir::{Proof, Transcript};

pub mod shuffle;
pub trait CommitmentSerde {
    fn size(&self) -> usize;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(buffer: &[u8], var_num: usize) -> Self;
}

pub trait PolyCommitProver<F: Field> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, poly: &Vec<F::BaseField>) -> Self;
    fn commit(&self) -> Self::Commitment;
    fn open(&self, pp: &Self::Param, point: &[F], transcript: &mut Transcript);
}

pub trait PolyCommitVerifier<F: Field> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, commit: Self::Commitment) -> Self;
    fn verify(
        &self,
        pp: &Self::Param,
        point: &[F],
        eval: F,
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
        let prover = ShufflePcProver::new(&(), &poly_evals);
        let commitment = prover.commit();
        let mut buffer = vec![0u8; commitment.size()];
        commitment.serialize_into(&mut buffer);

        transcript.append_u8_slice(&buffer, commitment.size());
        transcript.append_f(eval);
        prover.open(&(), &point, &mut transcript);
        let mut proof = transcript.proof;

        let commitment = RawCommitment::deserialize_from(&proof.bytes, 12);
        let mut transcript = Transcript::new();
        transcript.append_u8_slice(&proof.bytes, commitment.size());
        proof.step(commitment.size());
        let verifier = ShufflePcVerifier::new(&(), commitment);
        let eval = proof.get_next_and_step();
        assert!(verifier.verify(&(), &point, eval, &mut transcript, &mut proof));
    }
}
