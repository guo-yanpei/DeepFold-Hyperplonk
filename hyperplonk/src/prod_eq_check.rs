use arithmetic::{field::Field, poly::MultiLinearPoly};
use seal_fhe::{Asym, BFVEncoder, BFVEvaluator, Ciphertext, Context, Decryptor, EncryptionParameters, Encryptor, Plaintext};
use util::{fiat_shamir::{Proof, Transcript}, random_oracle::RandomOracle};

use crate::ct_sumcheck::Sumcheck;

type F = Plaintext;
type Q = Ciphertext;

pub struct ProdEqCheck;

impl<'a> ProdEqCheck {
    pub fn prove(evals: [Vec<Q>; 2], params: &'a EncryptionParameters, ctx: &'a Context, 
        encoder: &'a BFVEncoder, oracle: &'a RandomOracle,
        evaluator: &'a BFVEvaluator, encryptor: &'a Encryptor<Asym>) -> (Vec<F>, Vec<Q>, Vec<Vec<[Vec<Q>; 2]>>) {
        // let encoder = BFVEncoder::new(ctx, params).unwrap();
        let var_num = evals[0].len().ilog2() as usize;
        let mut transcript = vec![];
        let mut products = evals.map(|x| vec![x]);
        for i in 0..2 {
            for j in 1..var_num {
                let last_prod = &products[i][j - 1];
                let mut evals = vec![];
                let m = 1 << (var_num - j);
                for k in 0..m {
                    evals.push(last_prod[k*2].mult(&last_prod[k*2+1], evaluator));
                    // evals.push(F::mult(&last_prod[k * 2], &last_prod[k * 2 + 1], &encoder));
                }
                products[i].push(evals);
            }
            transcript.push(products[i][var_num-1][0].clone());
            transcript.push(products[i][var_num-1][1].clone());
            // transcript.append_f(products[i][var_num - 1][0].clone());
            // transcript.append_f(products[i][var_num - 1][1].clone());
        }
        // let mut point = vec![transcript.challenge_f(ctx)];
        let mut point = vec![oracle.folding_challenges[0].clone()];
        // let mut point1 = vec![];

        let mut total_sums = vec![];
        for i in (0..var_num - 1).rev() {
            let eq = MultiLinearPoly::new_eq(&point, params, ctx); // Todo: ?
            let mut evals_00 = vec![];
            let mut evals_01 = vec![];
            for j in products[0][i].iter().enumerate() {
                if j.0 % 2 == 0 {
                    evals_00.push(j.1.clone());
                } else {
                    evals_01.push(j.1.clone());
                }
            }
            let mut evals_10 = vec![];
            let mut evals_11 = vec![];
            for j in products[1][i].iter().enumerate() {
                if j.0 % 2 == 0 {
                    evals_10.push(j.1.clone());
                } else {
                    evals_11.push(j.1.clone());
                }
            }

            let (mut new_point, v, total_sum) = Sumcheck::prove(
                [evals_00, evals_01, evals_10, evals_11, eq.evals.iter().map(|x| encryptor.encrypt(x).unwrap()).collect()],
                3,
                // transcript,
                |v: [Q; 5]| [v[0].mult(&v[1], evaluator).mult(&v[4], evaluator), v[2].mult(&v[3], evaluator).mult(&v[4], evaluator)],
                ctx,
                encoder,
                oracle,
                evaluator,
                encryptor
            );
            total_sums.push(total_sum);
            for j in 0..4 {
                transcript.push(v[j].clone());
            }
            // let r = transcript.challenge_f(ctx);
            let r = oracle.folding_challenges[i].clone();
            point = vec![r];
            point.append(&mut new_point);
        }
        (point, transcript, total_sums)
    }

    pub fn verify(
        var_num: usize,
        transcript: Vec<Q>,
        // proof: &mut Proof,
        total_sums: Vec<Vec<[Vec<Q>; 2]>>,
        params: &EncryptionParameters,
        ctx: &Context,
        encoder: &BFVEncoder,
        oracle: &RandomOracle,
        evaluator: &BFVEvaluator,
        encryptor: &Encryptor<Asym>,
        decryptor: &Decryptor,
    ) -> (Vec<F>, [F; 2]) {
        // let mut v0: F = proof.get_next_and_step(ctx);
        // let mut v1: F = proof.get_next_and_step(ctx);
        // let mut v2: F = proof.get_next_and_step(ctx);
        // let mut v3: F = proof.get_next_and_step(ctx);
        let mut v0 = transcript[0].decrypt(decryptor);
        let mut v1 = transcript[1].decrypt(decryptor);
        let mut v2 = transcript[2].decrypt(decryptor);
        let mut v3 = transcript[3].decrypt(decryptor);

        // let encoder = BFVEncoder::new(ctx, params).unwrap();

        // assert_eq!(v0 * v1, v2 * v3);
        assert_eq!(v0.mult(&v1, encoder).get_value(encoder)[0], v2.mult(&v3, encoder).get_value(encoder)[0]);
        // transcript.push(v0);
        // transcript.push(v1);
        // transcript.push(v2);
        // transcript.push(v3);
        // let mut point = vec![transcript.challenge_f(ctx)];
        let mut point = vec![oracle.folding_challenges[0].clone()];
        let mut y = [
            v1.sub(&v0, encoder).mult(&point[0], encoder).add(&v0, encoder),
            v3.sub(&v2, encoder).mult(&point[0], encoder).add(&v2, encoder),
            // F::add(&v0, &F::mult(&F::sub(&v1, &v0, &encoder), &point[0], &encoder), &encoder),
            // F::add(&v2, &F::mult(&F::sub(&v3, &v2, &encoder), &point[0], &encoder), &encoder)
        ];
        for i in 1..var_num {
            let sums = total_sums[i-1].clone();
            let pts_sums = Sumcheck::decrypt_sums(sums, decryptor);
            let (mut new_point, new_y) = Sumcheck::verify(y, 3, i, pts_sums, params, ctx, &encoder, oracle, evaluator, encryptor, decryptor);
            // v0 = proof.get_next_and_step(ctx);
            // v1 = proof.get_next_and_step(ctx);
            v0 = transcript[4*i].decrypt(decryptor);
            v1 = transcript[4*i+1].decrypt(decryptor);
            assert_eq!(
                v0.mult(&v1, &encoder).mult(&MultiLinearPoly::eval_eq(&new_point, &point, &encoder), encoder).get_value(encoder)[0],
                new_y[0].get_value(encoder)[0]
            );
            // transcript.append_f(v0);
            // transcript.append_f(v1);
            // v2 = proof.get_next_and_step(ctx);
            // v3 = proof.get_next_and_step(ctx);
            v2 = transcript[4*i+2].decrypt(decryptor);
            v3 = transcript[4*i+3].decrypt(decryptor);
            assert_eq!(
                v2.mult(&v3, &encoder).mult(&MultiLinearPoly::eval_eq(&new_point, &point, &encoder), &encoder).get_value(encoder)[0],
                new_y[1].get_value(encoder)[0]
            );
            // transcript.append_f(v2);
            // transcript.append_f(v3);
            // let r = transcript.challenge_f(ctx);
            let r = oracle.folding_challenges[var_num-i-1].clone();
            point = vec![r.clone()];
            point.append(&mut new_point);
            y = [
                // F::add(&v0, &F::mult(&F::sub(&v1, &v0, &encoder), &r, &encoder), &encoder),
                // F::add(&v2, &F::mult(&F::sub(&v3, &v2, &encoder), &r, &encoder), &encoder),
                v1.sub(&v0, encoder).mult(&r, encoder).add(&v0, encoder),
                v3.sub(&v2, encoder).mult(&r, encoder).add(&v2, encoder),
            ]
            // y = [v0 + (v1 - v0) * r, v2 + (v3 - v2) * r];
        }
        (point, y)
    }
}

#[cfg(test)]
mod tests {
    use arithmetic::{
        // field::{goldilocks64::Goldilocks64Ext, Field},
        poly::MultiLinearPoly,
    };
    use rand::thread_rng;
    use util::{fiat_shamir::Transcript, random_oracle::RandomOracle};

    use super::ProdEqCheck;

    use seal_fhe::{
        Asym, BFVEncoder, BFVEvaluator, BfvEncryptionParametersBuilder, Ciphertext, CoefficientModulus, Context, Decryptor, EncryptionParameters, Encryptor, KeyGenerator, PlainModulus, Plaintext, SecurityLevel
    };

    type F = Plaintext;
    type Q = Ciphertext;

    // use super::SumcheckVerifier;
    const VN: usize = 2;
    const BATCH_SIZE: u64 = 1 << 14;
    const CIPHER_BIT_VEC: &[i32] = &[50; 7];

    fn gen_params_n_ctx() -> (EncryptionParameters, Context) {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(BATCH_SIZE)
            .set_coefficient_modulus(
                CoefficientModulus::create(BATCH_SIZE, CIPHER_BIT_VEC).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(BATCH_SIZE, 20).unwrap())
            .build()
            .unwrap(); 

        let ctx = Context::new(&params, false, SecurityLevel::TC128).unwrap();
        (params, ctx)
    }

    #[test]
    fn prod_check() {
        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let oracle = RandomOracle::new(VN, 0, &ctx, &params, &key_gen);
        let evaluator = BFVEvaluator::new(&ctx).unwrap();
        let encryptor = Encryptor::<Asym>::new(&ctx, &key_gen.create_public_key()).unwrap();
        let decryptor = Decryptor::new(&ctx, &key_gen.secret_key()).unwrap();

        // let mut transcript = Transcript::new();
        let mut rng = thread_rng();
        let evals = (0..1<<VN)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let pt_evals = evals.iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<F>>();
        let evals_rev = evals.clone().into_iter().rev().collect::<Vec<_>>();
        let pt_evals_rev = pt_evals.clone().into_iter().rev().collect::<Vec<_>>();
        let (point, transcript, total_sums) = ProdEqCheck::prove([evals.clone(), evals_rev.clone()], &params, &ctx, &encoder, &oracle, &evaluator, &encryptor);
        // let mut proof = transcript.proof;

        // let mut transcript = Transcript::new();
        let (new_point, y) = ProdEqCheck::verify(VN, transcript, total_sums, &params, &ctx, &encoder, &oracle, &evaluator, &encryptor, &decryptor);
        assert_eq!(MultiLinearPoly::eval_multilinear_ext(&pt_evals, &point, &encoder), y[0]);
        assert_eq!(
            MultiLinearPoly::eval_multilinear_ext(&pt_evals_rev, &new_point, &encoder),
            y[1]
        );
    }
}
