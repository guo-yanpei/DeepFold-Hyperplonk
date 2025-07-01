use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitProver};
use seal_fhe::{BFVEncoder, Ciphertext, Context, EncryptionParameters, Plaintext};
use util::{fiat_shamir::{Proof, Transcript}, random_oracle::RandomOracle};

use crate::{prod_eq_check::ProdEqCheck, sumcheck::Sumcheck};

type F = Plaintext;
type Q = Ciphertext;

pub struct ProverKey<'a, PC: PolyCommitProver> {
    pub selector: MultiLinearPoly<'a>,
    pub commitments: PC,
    pub permutation: [MultiLinearPoly<'a>; 3],
}

pub struct Prover<'a, PC: PolyCommitProver> {
    pub prover_key: ProverKey<'a, PC>,
    pub ctx: &'a Context,
    pub params: &'a EncryptionParameters,
    pub encoder: BFVEncoder<'a>,
    pub oracle: &'a RandomOracle<'a>,
}

impl<'a, PC: PolyCommitProver> Prover<'a, PC> {
    pub fn new(prover_key: ProverKey<'a, PC>, ctx: &'a Context, params: &'a EncryptionParameters, oracle: &'a RandomOracle) -> Self {
        Self {
            prover_key,
            ctx,
            params,
            encoder: BFVEncoder::new(ctx, params).unwrap(),
            oracle,
        }
    }

    pub fn prove(&self, pp: &PC::Param, nv: usize, 
        witness: [Vec<F>; 3], params: &'a EncryptionParameters, 
        ctx: &'a Context, encoder: &'a BFVEncoder, oracle: &'a RandomOracle) -> (Vec<[Vec<F>; 1]>, Vec<Vec<[Vec<F>; 2]>>, Vec<F>, Vec<[Vec<Plaintext>; 2]>, Vec<F>) {

        // 0. setup: initialize fiat shamir and commit witness
        // let mut transcript = Transcript::new();
        // let witness_pc = PC::new(pp, &witness);

        // let commit = witness_pc.commit();
        // let mut buffer = vec![0u8; PC::Commitment::size(nv, 3)];
        // commit.serialize_into(&mut buffer);
        // transcript.append_u8_slice(&buffer, PC::Commitment::size(nv, 3));

        let mut transcript = vec![];

        let bookkeeping = witness
            .clone()
            .map(|x| x.into_iter().map(|i| i).collect::<Vec<_>>());

        // 1. generate challenge vector and eq polynomial
        // let r = (0..nv)
        //     .map(|_| transcript.challenge_f(self.ctx))
        //     .collect::<Vec<_>>();
        let r = (0..nv).map(|i| oracle.folding_challenges[i].clone()).collect::<Vec<_>>();
        let eq_r = MultiLinearPoly::new_eq(&r, self.params, self.ctx);

        // 2. sumcheck prove:
        // 2.1 evals are: all prover keys (selectors), L poly, R poly, O poly, eq evals
        // 2.2 f is the target function: eq((1-selector)*(l+r) + selector*l*r + minus_o)
        let (sumcheck_point, v, total_sums) = Sumcheck::prove(
            [
                self.prover_key
                    .selector
                    .evals
                    .iter()
                    .map(|x| x.clone())
                    .collect(),
                bookkeeping[0].clone(),
                bookkeeping[1].clone(),
                bookkeeping[2].clone(),
                eq_r.evals.clone(),
            ],
            4,
            // &mut transcript,
            // |v: [F; 5]| [v[4] * ((1 - v[0]) * (v[1] + v[2]) + v[0] * v[1] * v[2] + v[3])],
            |v: [F; 5]| [
                F::from_int(1, &encoder).sub(&v[0], &encoder).mult(&v[1].add(&v[2], &encoder), &encoder)
                    .add(&v[0].mult(&v[1], &encoder).mult(&v[2], &encoder), &encoder).add(&v[3], &encoder)
                    .mult(&v[4], &encoder)
            ],
            ctx,
            encoder,
            oracle,
        );

        for i in 0..4 {
            transcript.push(v[i].clone());
        }
        let witness_flatten = bookkeeping[0]
            .clone()
            .into_iter()
            .chain(bookkeeping[1].clone().into_iter())
            .chain(bookkeeping[2].clone().into_iter())
            .chain((0..(1 << nv)).into_iter().map(|_| F::from_int(0, &self.encoder)))
            .collect::<Vec<_>>();
        let identical = MultiLinearPoly::new_identical(nv, F::from_int(0, &self.encoder), self.params, self.ctx)
            .evals
            .into_iter()
            .chain(
                MultiLinearPoly::new_identical(nv, F::from_int(1 << 29, &self.encoder), self.params, self.ctx)
                    .evals
                    .into_iter(),
            )
            .chain(
                MultiLinearPoly::new_identical(nv, F::from_int(1 << 30, &self.encoder), self.params, self.ctx)
                    .evals
                    .into_iter(),
            )
            .chain((0..(1 << nv)).into_iter().map(|_| F::from_int(0, &self.encoder)))
            .collect::<Vec<_>>();
        let permutation = self.prover_key.permutation[0]
            .clone()
            .evals
            .into_iter()
            .chain(self.prover_key.permutation[1].clone().evals.into_iter())
            .chain(self.prover_key.permutation[2].clone().evals.into_iter())
            .chain((0..(1 << nv)).into_iter().map(|_| F::from_int(0, &self.encoder)))
            .collect::<Vec<_>>();

        // let r = [0; 2].map(|_| transcript.challenge_f(self.ctx));

        let r_0 = r[0].clone().get_value(encoder)[0];
        let evals1 = witness_flatten
            .iter()
            .zip(identical.iter())
            .map(|(x, y)| F::add(&F::add(&r[0], &x, &self.encoder), &F::mult(&r[1], &y, &self.encoder), &self.encoder))
            .collect::<Vec<_>>();
        let evals2 = witness_flatten
            .iter()
            .zip(permutation.iter())
            .map(|(x, y)| F::add(&F::add(&r[0], &x, &self.encoder), &F::mult(&r[1], &y, &self.encoder), &self.encoder))
            .collect::<Vec<_>>();
        let (prod_point, prod_transcript, prod_total_sums) = ProdEqCheck::prove([evals1, evals2], params, ctx, encoder, oracle);

        for i in 0..3 {
            let v = MultiLinearPoly::eval_multilinear(
                &witness[i],
                &prod_point[..nv],
                &self.encoder
            );
            transcript.push(v);
        }
        for i in 0..3 {
            let v = MultiLinearPoly::eval_multilinear(
                &self.prover_key.permutation[i].evals,
                &prod_point[..nv],
                &self.encoder
            );
            transcript.push(v);
        }

        // let r: F = transcript.challenge_f(self.ctx);
        let r = oracle.folding_challenges[0].clone();
        let r2 = F::mult(&r, &r, &self.encoder);
        let r3 = F::mult(&r2, &r, &self.encoder);
        let r4 = F::mult(&r3, &r, &self.encoder);
        let r5 = F::mult(&r4, &r, &self.encoder);
        let (point, sc_evals, sc_total_sums) = Sumcheck::prove(
            [
                self.prover_key
                    .selector
                    .evals
                    .iter()
                    .zip(witness[0].iter())
                    .zip(witness[1].iter())
                    .zip(witness[2].iter())
                    .map(|(((x1, x2), x3), x4)| {
                        x1
                            .add(&r.mult(x2, &self.encoder), &self.encoder)
                            .add(&r2.mult(x3, &self.encoder), &self.encoder)
                            .add(&r3.mult(x4, &self.encoder), &self.encoder)
                            // + r.mul_base_elem(x2)
                            // + r2.mul_base_elem(x3)
                            // + r3.mul_base_elem(x4)
                    })
                    .collect(),
                self.prover_key.permutation[0]
                    .evals
                    .iter()
                    .zip(self.prover_key.permutation[1].evals.iter())
                    .zip(self.prover_key.permutation[2].evals.iter())
                    .zip(witness[0].iter())
                    .zip(witness[1].iter())
                    .zip(witness[2].iter())
                    .map(|(((((x1, x2), x3), x4), x5), x6)| {
                        let mul_elem1 = F::mult(&r, &x2, encoder);
                        let mul_elem2 = F::mult(&r2, &x3, encoder);
                        let mul_elem3 = F::mult(&r3, &x4, encoder);
                        let mul_elem4 = F::mult(&r4, &x5, encoder);
                        let mul_elem5 = F::mult(&r5, &x6, encoder);
                        [&mul_elem1, &mul_elem2, &mul_elem3, &mul_elem4, &mul_elem5].into_iter().fold(x1.clone(), |x, y| F::add(&x, &y, encoder))
                        // F::from(x1)
                        //     + r.mul_base_elem(x2)
                        //     + r2.mul_base_elem(x3)
                        //     + r3.mul_base_elem(x4)
                        //     + r4.mul_base_elem(x5)
                        //     + r5.mul_base_elem(x6)
                    })
                    .collect(),
                MultiLinearPoly::new_eq(&sumcheck_point, params, ctx).evals,
                MultiLinearPoly::new_eq(&prod_point[..nv].to_vec(), params, ctx).evals,
            ],
            2,
            // &mut transcript,
            |v: [F; 4]| [F::mult(&v[0], &v[2], encoder), F::mult(&v[1], &v[3], encoder)],
            self.ctx,
            &self.encoder,
            self.oracle
        );

        transcript.push(MultiLinearPoly::eval_multilinear(
            &self.prover_key.selector.evals,
            &point,
            &self.encoder,
        ));
        for i in 0..3 {
            transcript.push(MultiLinearPoly::eval_multilinear(
                &self.prover_key.permutation[i].evals,
                &point,
                &self.encoder
            ));
        }
        for i in 0..3 {
            transcript.push(MultiLinearPoly::eval_multilinear(&witness[i], &point, &self.encoder));
        }

        // PC::open(
        //     pp,
        //     vec![&self.prover_key.commitments, &witness_pc],
        //     point,
        //     &mut transcript,
        // );

        (total_sums, prod_total_sums, prod_transcript, sc_total_sums, transcript)
    }
}
