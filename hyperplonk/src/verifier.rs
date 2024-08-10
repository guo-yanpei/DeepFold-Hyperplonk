use std::marker::PhantomData;

use arithmetic::field::Field;
use poly_commit::{CommitmentSerde, PolyCommitVerifier};
use util::fiat_shamir::{Proof, Transcript};

use crate::sumcheck::Sumcheck;

pub struct VerifierKey<F: Field, PC: PolyCommitVerifier<F>> {
    pub selector_commitment: PC,
    pub permutation_commitments: [PC; 3],
    pub _data: PhantomData<F>,
}

pub struct Verifier<F: Field, PC: PolyCommitVerifier<F>> {
    pub verifier_key: VerifierKey<F, PC>,
}

impl<F: Field, PC: PolyCommitVerifier<F>> Verifier<F, PC> {
    pub fn verify(&self, mut proof: Proof) -> bool {
        let mut transcript = Transcript::new();
        let witness_0 = PC::Commitment::deserialize_from(&proof.bytes, 12);
        transcript.append_u8_slice(&proof.bytes, witness_0.size());
        proof.step(witness_0.size());
        let witness_1 = PC::Commitment::deserialize_from(&proof.bytes, 12);
        transcript.append_u8_slice(&proof.bytes, witness_1.size());
        proof.step(witness_1.size());
        let witness_2 = PC::Commitment::deserialize_from(&proof.bytes, 12);
        transcript.append_u8_slice(&proof.bytes, witness_2.size());
        proof.step(witness_2.size());
        let r = (0..12).map(|_| transcript.challenge_f::<F>()).collect::<Vec<_>>();
        let (point, y) = Sumcheck::verify(F::zero(), 4, 12, &mut transcript, &mut proof);
        true
    }
}
