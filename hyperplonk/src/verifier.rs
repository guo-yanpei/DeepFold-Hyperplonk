use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitVerifier};
use seal_fhe::{BFVEncoder, Ciphertext, Context, EncryptionParameters, Plaintext};
use util::{fiat_shamir::{Proof, Transcript}, random_oracle::RandomOracle};

use crate::{prod_eq_check::ProdEqCheck, sumcheck::Sumcheck};

type F = Plaintext;
type Q = Ciphertext;

pub struct VerifierKey<PC: PolyCommitVerifier> {
    pub commitment: PC,
}

pub struct Verifier<'a, PC: PolyCommitVerifier> {
    pub verifier_key: VerifierKey<PC>,
    pub ctx: &'a Context,
    pub params: &'a EncryptionParameters,
    pub encoder: BFVEncoder<'a>,
    pub oracle: &'a RandomOracle<'a>
}

impl<'a, PC: PolyCommitVerifier> Verifier<'a, PC> {
    pub fn new(verifier_key: VerifierKey<PC>, params: &'a EncryptionParameters, ctx: &'a Context, oracle: &'a RandomOracle) -> Self {
        Self {
            verifier_key,
            ctx,
            params,
            encoder: BFVEncoder::new(ctx, params).unwrap(),
            oracle,
        }
    }

    pub fn verify(&self, pp: &PC::Param, nv: usize, 
        transcript: Vec<Plaintext>, total_sums: Vec<[Vec<F>; 1]>, 
        prod_total_sums: Vec<Vec<[Vec<Plaintext>; 2]>>, sc_total_sums: Vec<[Vec<Plaintext>; 2]>, prod_transcript: Vec<F>) -> bool {
        let encoder = &self.encoder;

        let rs = (0..nv)
            .map(|i| self.oracle.folding_challenges[i].clone())
            .collect::<Vec<_>>();
        let (sumcheck_point, claim_y) =
            Sumcheck::verify([F::from_int(0, encoder)], 4, nv, total_sums, self.params, self.ctx, &self.encoder, self.oracle);
        let claim_s = transcript[0].clone();
        let claim_w0 = transcript[1].clone();
        let claim_w1 = transcript[2].clone();
        let claim_w2 = transcript[3].clone();
        let eq_v = MultiLinearPoly::eval_eq(&rs, &sumcheck_point, &self.encoder);

        // let p1 = [&F::sub(&F::from_int(1, &self.encoder), &claim_s, &self.encoder), &F::add(&claim_w0, &claim_w1, &self.encoder)].into_iter()
        //     .fold(eq_v.clone(), |x, y| F::mult(&x, y, &self.encoder));
        // let p2 = [&claim_w0, &claim_w1].into_iter().fold(claim_s.clone(), |x, y| F::mult(&x, y, &self.encoder));
        assert_eq!(
            claim_y[0].clone(),
            // [&p2, &claim_w2].into_iter().fold(p1.clone(), |x, y| x.add(y, &self.encoder))
            F::from_int(1, encoder).sub(&claim_s, encoder)
                .mult(&claim_w0.add(&claim_w1, encoder), encoder)
                .add(&claim_s.mult(&claim_w0.mult(&claim_w1, encoder), encoder), encoder)
                .add(&claim_w2, encoder)
                .mult(&eq_v, encoder)
            // eq_v * ((F::one() - claim_s) * (claim_w0 + claim_w1)
            //     + claim_s * claim_w0 * claim_w1
            //     + claim_w2)
        );

        // let r_1: F = transcript.challenge_f(self.ctx);
        // let r_2: F = transcript.challenge_f(self.ctx);
        let r_1 = rs[0].clone();
        let r_2 = rs[1].clone();

        let (prod_point, y) = ProdEqCheck::verify(nv + 2, prod_transcript, prod_total_sums, self.params, self.ctx, &self.encoder, self.oracle);
        let witness_eval = [0,1,2].map(|i| {
            // let x: F = proof.get_next_and_step(self.ctx);
            let x = transcript[4+i].clone();
            // transcript.append_f(x);
            x
        });
        let perm_eval = [0,1,2].map(|i| {
            // let x: F = proof.get_next_and_step(self.ctx);
            let x = transcript[7+i].clone();
            // transcript.append_f(x);
            x
        });
        let v = vec![
            r_2.clone()
                .mult(&MultiLinearPoly::eval_identical(&prod_point[..nv].to_vec(), F::from_int(0, encoder), encoder), encoder)
                .add(&r_1, encoder)
                .add(&witness_eval[0], encoder),
            r_2.clone()
                .mult(&MultiLinearPoly::eval_identical(&prod_point[..nv].to_vec(), F::from_int(1 << 29, encoder), encoder), encoder)
                .add(&r_1, encoder)
                .add(&witness_eval[1], encoder),
            r_2.clone()
                .mult(&MultiLinearPoly::eval_identical(&prod_point[..nv].to_vec(), F::from_int(1 << 30, encoder), encoder), encoder)
                .add(&r_1, encoder)
                .add(&witness_eval[2], encoder),
            r_1.clone()
        ];
        assert_eq!(y[0], MultiLinearPoly::eval_multilinear_ext(&v, &prod_point[nv..], encoder));

        let v1 = [&witness_eval[0], &F::mult(&r_2, &perm_eval[0], encoder)]
            .into_iter().fold(r_1.clone(), |x, y| F::add(&x, y, encoder));
        let v2 = [&witness_eval[1], &F::mult(&r_2, &perm_eval[1], encoder)]
            .into_iter().fold(r_1.clone(), |x, y| F::add(&x, y, encoder));
        let v3 = [&witness_eval[2], &F::mult(&r_2, &perm_eval[2], encoder)]
            .into_iter().fold(r_1.clone(), |x, y| F::add(&x, y, encoder));
        let vec = vec![v1, v2, v3, r_1.clone()];
        assert_eq!(y[1], MultiLinearPoly::eval_multilinear_ext(&vec, &prod_point[nv..], &self.encoder));
        let r = rs[0].clone();
        let y1 = F::add(&claim_s, &F::mult(
            &r, &F::add(
                &claim_w0, &F::mult(
                    &r, &F::add(
                        &claim_w1,
                        &F::mult(&r, &claim_w2, encoder), encoder),
                        encoder), 
                    encoder), 
                encoder), 
            encoder);
        let y2 = F::add(&perm_eval[0], &F::mult(
                &r, &F::add(
                    &perm_eval[1], &F::mult(
                        &r, &F::add(
                            &perm_eval[2], &F::mult(
                                &r, &F::add(
                                    &witness_eval[0], &F::mult(
                                        &r, &F::add(
                                            &witness_eval[1], &F::mult(&r, &witness_eval[2], encoder), encoder),
                                        encoder), 
                                    encoder), 
                                encoder), 
                            encoder), 
                        encoder),
                    encoder),
                encoder),
            encoder);
            // [
            //     claim_s + r * (claim_w0 + r * (claim_w1 + r * claim_w2)),
            //     perm_eval[0]
            //         + r * (perm_eval[1]
            //             + r * (perm_eval[2]
            //                 + r * (witness_eval[0] + r * (witness_eval[1] + r * witness_eval[2])))),
            // ]
        let vec = [y1, y2];
        let (point, y) = Sumcheck::verify(
            vec,
            2,
            nv,
            sc_total_sums,
            self.params,
            self.ctx,
            &self.encoder,
            self.oracle
        );
        // let claim_s: F = proof.get_next_and_step(self.ctx);
        // transcript.append_f(claim_s);
        let claim_s = transcript[10].clone();
        let perm_eval = [0,1,2].map(|i| {
            // let x: F = proof.get_next_and_step(self.ctx);
            let x = transcript[11+i].clone();
            // transcript.append_f(x);
            x
        });
        let witness_eval = [0,1,2].map(|i| {
            // let x: F = proof.get_next_and_step(self.ctx);
            let x = transcript[14+i].clone();
            // transcript.append_f(x);
            x
        });
        assert_eq!(y[0],
            witness_eval[2].clone()
                .mult(&r, encoder)
                .add(&witness_eval[1], encoder)
                .mult(&r, encoder)
                .add(&witness_eval[0], encoder)
                .mult(&r, encoder)
                .add(&claim_s, encoder)
                .mult(&MultiLinearPoly::eval_eq(&sumcheck_point, &point, encoder), encoder)
        );
        assert_eq!(
            y[1],
            witness_eval[2].clone()
                .mult(&r, encoder)
                .add(&witness_eval[1], encoder)
                .mult(&r, encoder)
                .add(&witness_eval[0], encoder)
                .mult(&r, encoder)
                .add(&perm_eval[2], encoder)
                .mult(&r, encoder)
                .add(&perm_eval[1], encoder)
                .mult(&r, encoder)
                .add(&perm_eval[0], encoder)
                .mult(&MultiLinearPoly::eval_eq(&prod_point[..nv].to_vec(), &point, encoder), encoder)
        );
        // PC::verify(
        //     pp,
        //     vec![&self.verifier_key.commitment, &witness_pc],
        //     point,
        //     vec![
        //         vec![claim_s, perm_eval[0], perm_eval[1], perm_eval[2]],
        //         vec![witness_eval[0], witness_eval[1], witness_eval[2]],
        //     ],
        //     &mut transcript,
        //     &mut proof,
        // );
        true
    }
}
