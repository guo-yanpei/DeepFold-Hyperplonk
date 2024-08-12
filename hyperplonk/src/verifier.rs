use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitVerifier};
use util::fiat_shamir::{Proof, Transcript};

use crate::{prod_eq_check::ProdEqCheck, sumcheck::Sumcheck};

pub struct VerifierKey<F: Field, PC: PolyCommitVerifier<F>> {
    pub selector_commitment: PC,
    pub permutation_commitments: [PC; 3],
    pub _data: PhantomData<F>,
}

pub struct Verifier<F: Field, PC: PolyCommitVerifier<F>> {
    pub verifier_key: VerifierKey<F, PC>,
}

impl<F: Field, PC: PolyCommitVerifier<F>> Verifier<F, PC> {
    pub fn verify(&self, pp: &PC::Param, nv: usize, mut proof: Proof) -> bool {
        let mut transcript = Transcript::new();
        let witness_0 = PC::Commitment::deserialize_from(&mut proof, nv);
        let mut buffer = vec![0u8; witness_0.size()];
        witness_0.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_0.size());
        let witness_0 = PC::new(pp, witness_0);

        let witness_1 = PC::Commitment::deserialize_from(&mut proof, nv);
        let mut buffer = vec![0u8; witness_1.size()];
        witness_1.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_1.size());

        let witness_2 = PC::Commitment::deserialize_from(&mut proof, nv);
        let mut buffer = vec![0u8; witness_2.size()];
        witness_2.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, witness_2.size());

        let r = (0..nv)
            .map(|_| transcript.challenge_f::<F>())
            .collect::<Vec<_>>();
        let (point, claim_y) = Sumcheck::verify([F::zero()], 4, nv, &mut transcript, &mut proof);
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
            claim_y[0],
            eq_v * ((F::one() - claim_s) * (claim_w0 + claim_w1)
                + claim_s * claim_w0 * claim_w1
                + claim_w2)
        );

        let r_1: F = transcript.challenge_f();
        let r_2: F = transcript.challenge_f();

        let (prod_point, y) = ProdEqCheck::verify::<F>(nv + 2, &mut transcript, &mut proof);
        let witness_eval = [0; 3].map(|_| {
            let x: F = proof.get_next_and_step();
            transcript.append_f(x);
            x
        });
        let perm_eval = [0; 3].map(|_| {
            let x: F = proof.get_next_and_step();
            transcript.append_f(x);
            x
        });

        assert_eq!(y[0], {
            let v = vec![
                r_1 + witness_eval[0]
                    + r_2 * MultiLinearPoly::eval_identical(&prod_point[..nv].to_vec(), F::zero()),
                r_1 + witness_eval[1]
                    + r_2
                        * MultiLinearPoly::eval_identical(
                            &prod_point[..nv].to_vec(),
                            F::from(1 << 29),
                        ),
                r_1 + witness_eval[2]
                    + r_2
                        * MultiLinearPoly::eval_identical(
                            &prod_point[..nv].to_vec(),
                            F::from(1 << 30),
                        ),
                r_1,
            ];
            MultiLinearPoly::eval_multilinear_ext(&v, &prod_point[nv..])
        });
        assert_eq!(y[1], {
            let v = vec![
                r_1 + witness_eval[0] + r_2 * perm_eval[0],
                r_1 + witness_eval[1] + r_2 * perm_eval[1],
                r_1 + witness_eval[2] + r_2 * perm_eval[2],
                r_1,
            ];
            MultiLinearPoly::eval_multilinear_ext(&v, &prod_point[nv..])
        });
        true
    }
}
