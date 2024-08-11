use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitVerifier};
use util::fiat_shamir::{Proof, Transcript};

use crate::{prod_check::ProdCheck, sumcheck::Sumcheck};

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
        let (point, claim_y) = Sumcheck::verify(F::zero(), 4, 12, &mut transcript, &mut proof);
        let claim_s: F = proof.get_next_and_step();
        transcript.append_f(claim_s);
        let claim_w0: F = proof.get_next_and_step();
        transcript.append_f(claim_w0);
        let claim_w1: F = proof.get_next_and_step();
        transcript.append_f(claim_w1);
        let claim_w2: F = proof.get_next_and_step();
        transcript.append_f(claim_w2);
        let eq_v = MultiLinearPoly::eval_eq(&r, &point);
        assert_eq!(
            claim_y,
            eq_v * ((F::one() - claim_s) * (claim_w0 + claim_w1)
                + claim_s * claim_w0 * claim_w1
                + claim_w2)
        );

        let r_1: F = transcript.challenge_f();
        let r_2: F = transcript.challenge_f();

        let (prod_1, point_1, claim_1) = ProdCheck::verify::<F>(13, &mut transcript, &mut proof);
        let (prod_2, point_2, claim_2) = ProdCheck::verify::<F>(12, &mut transcript, &mut proof);
        let (prod_3, point_3, claim_3) = ProdCheck::verify::<F>(13, &mut transcript, &mut proof);
        let (prod_4, point_4, claim_4) = ProdCheck::verify::<F>(12, &mut transcript, &mut proof);
        assert_eq!(prod_1 * prod_2, prod_3 * prod_4);
        true
    }
}
