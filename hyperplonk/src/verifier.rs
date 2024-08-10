use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
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
        let witness_0 = PC::Commitment::deserialize_from(&mut proof, 12);
        let mut buffer = vec![0u8; witness_0.size()];
        witness_0.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_0.size());

        let witness_1 = PC::Commitment::deserialize_from(&mut proof, 12);
        let mut buffer = vec![0u8; witness_1.size()];
        witness_1.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_1.size());

        let witness_2 = PC::Commitment::deserialize_from(&mut proof, 12);
        let mut buffer = vec![0u8; witness_2.size()];
        witness_2.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_2.size());
        
        let r = (0..12)
            .map(|_| transcript.challenge_f::<F>())
            .collect::<Vec<_>>();
        let (point, y) = Sumcheck::verify(F::zero(), 4, 12, &mut transcript, &mut proof);
        let s: F = proof.get_next_and_step();
        transcript.append_f(s);
        let v_0: F = proof.get_next_and_step();
        transcript.append_f(v_0);
        let v_1: F = proof.get_next_and_step();
        transcript.append_f(v_1);
        let v_2: F = proof.get_next_and_step();
        transcript.append_f(v_2);
        let eq_v = MultiLinearPoly::eval_eq(&r, &point);
        assert_eq!(
            y,
            eq_v * ((F::one() - s) * (v_0 + v_1) + s * v_0 * v_1 + v_2)
        );
        true
    }
}
