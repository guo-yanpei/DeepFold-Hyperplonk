use arithmetic::{field::{batch_inverse, dynamic_field::DynamicField, Field}, poly};
use seal_fhe::{Asym, BFVEncoder, BFVEvaluator, Ciphertext, Context, Decryptor, EncryptionParameters, Encryptor, Evaluator, Plaintext};
use util::{fiat_shamir::{Proof, Transcript}, random_oracle::RandomOracle};

pub struct Sumcheck;

type F = Plaintext;
type Q = Ciphertext;

type T = DynamicField;

impl<'a> Sumcheck {
    fn fold_next_domain(poly_evals: &mut Vec<Q>, m: usize, challenge: F, encoder: &'a BFVEncoder, evaluator: &BFVEvaluator) {
        for j in 0..m {
            // poly_evals[j] = F::add(&poly_evals[j*2], &F::mult(&F::sub(&poly_evals[j*2+1], &poly_evals[j*2], encoder), &challenge, encoder), encoder);
                // poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
                poly_evals[j] = evaluator.add(&poly_evals[j*2], &evaluator.multiply_plain(&evaluator.sub(&poly_evals[j*2+1], &poly_evals[j*2]).unwrap(), &challenge).unwrap()).unwrap()
        }
        poly_evals.truncate(m)
    }

    // N: 5 (l, r, o, selector, eq; degree of polynomial+1); M: 1
    pub fn prove<const N: usize, const M: usize, FUNC: Fn([Q; N]) -> [Q; M]>(
        mut evals: [Vec<Q>; N],
        degree: usize,
        // transcript: &mut Transcript,
        f: FUNC,
        ctx: &'a Context,
        encoder: &BFVEncoder,
        oracle: &RandomOracle,
        evaluator: &BFVEvaluator,
        encryptor: &Encryptor<Asym>,
    ) -> (Vec<F>, [Q; N], Vec<[Vec<Q>; M]>) {
        let var_num = evals[0].len().ilog2() as usize;
        println!("var num: {}, prover M: {}", var_num, M);
        let mut new_point = vec![];
        let mut total_sums = vec![];
        for i in 0..var_num {
            let m = 1usize << (var_num - i);
            let sums = (0..m).step_by(2).fold(
                [0; M].map(|_| vec![Q::from_int(0, encoder, encryptor); degree + 1]),
                |mut acc, x| {
                    // compute evaluations on hypercube
                    let mut extrapolations = vec![];
                    for j in 0..N {
                        let v_0 = evals[j][x].clone();
                        let v_1 = evals[j][x + 1].clone();
                        let diff = v_1.sub(&v_0, evaluator);
                        let mut e = vec![v_0.clone(), v_1.clone()];
                        for k in 1..degree {
                            e.push(e[k].add(&diff, evaluator));
                        }
                        extrapolations.push(e);
                    }
                    for j in 0..degree + 1 {
                        let mut res = vec![extrapolations[0][j].clone()];
                        for k in 1..N {
                            res.push(extrapolations[k][j].clone());
                        }
                        let tmp = f(res.try_into().unwrap());
                        for k in 0..M {
                            acc[k][j] = acc[k][j].add(&tmp[k], evaluator);
                        }
                    }
                    acc
                },
            );
            total_sums.push(sums);
            // for j in 0..M {
            //     for k in &sums[j] {
            //         transcript.append_f(k.clone());
            //     }
            // }
            // let challenge = transcript.challenge_f(ctx);
            let challenge = &oracle.folding_challenges[i];
            new_point.push(challenge.clone());
            for j in evals.iter_mut() {
                Self::fold_next_domain(j, m / 2, challenge.clone(), encoder, evaluator)
            }
        }
        (new_point, evals.map(|x| x[0].clone()), total_sums)
    }

    fn init_base(n: usize, modulus: u64) -> Vec<T> {
        let mut res = vec![];
        for i in 0..n + 1 {
            let mut prod = T::from_with_modulus(1, modulus);
            for j in 0..n + 1 {
                if i != j {
                    prod *= T::from_with_modulus(i as u64, modulus) - T::from_with_modulus(j as u64, modulus);
                }
            }
            res.push(prod);
        }
        batch_inverse(&mut res);
        res
    }

    fn uni_extrapolate<Q: Field>(base: &Vec<Q>, v: &Vec<F>, x: F, encoder: &'a BFVEncoder) -> F {
        let n = base.len() - 1;
        // let mut prod = x;
        // for i in 1..n + 1 {
        //     prod = F::mult(&prod, &F::sub(&x, &F::from_int(i as u64, encoder), &encoder), &encoder) ;
        // }
        // let mut numerator = (0..n + 1)
        //     .map(|y| F::sub(&x, &F::from_int(y as u64, encoder), encoder))
        //     .collect::<Vec<_>>();
        // batch_inverse(&mut numerator);
        let mut numerator = vec![];
        for i in 0..n+1 {
            let mut prod = F::from_int(1, encoder);
            for j in 0..n+1 {
                if i != j {
                    prod = F::mult(&prod, &F::sub(&x, &F::from_int(j as u64, encoder), encoder), encoder)
                }
            }
            numerator.push(prod);
        }
        let mut res = F::from_int(0, encoder);
        for i in 0..n + 1 {
            res = F::add(&res, 
                &F::mult(&F::from_int(base[i].get_value(), encoder), &F::mult(&numerator[i], &v[i], encoder), encoder), encoder);
            // res += numerator[i] * base[i] * v[i];
        }
        // res * prod
        res
    }

    pub fn verify<const M: usize>(
        mut y: [Q; M],
        degree: usize,
        var_num: usize,
        total_sums: Vec<[Vec<Q>; M]>,
        // transcript: &mut Transcript,
        // proof: &mut Proof,
        params: &'a EncryptionParameters,
        ctx: &'a Context,
        encoder: &BFVEncoder,
        oracle: &RandomOracle,
        evaluator: &BFVEvaluator,
        encryptor: &Encryptor<Asym>,
        decryptor: &Decryptor,
    ) -> (Vec<F>, [F; M]) {
        let mut res = vec![];
        let mut yy = (0..M).map(|x| decryptor.decrypt(&y[x]).unwrap()).collect::<Vec<F>>();
        let modulus = params.get_plain_modulus().value();
        let base = Self::init_base(degree, modulus);
        for i in 0..var_num {
            // let sums = [0; M].map(|_| {
            //     let mut sum = vec![];
            //     for _ in 0..degree + 1 {
            //         let x = proof.get_next_and_step(ctx);
            //         transcript.append_f(x);
            //         sum.push(x);
            //     }
            //     sum
            // });
            println!("{} step entered, M is {}", i, M);
            let sums = total_sums[i].clone();
            let mut pts = vec![];
            for j in 0..M {
                println!("j: {}", j);
                let sc1 = decryptor.decrypt(&sums[j][0]).unwrap();
                let sc2 = decryptor.decrypt(&sums[j][1]).unwrap();
                pts.push(
                    sums[j].iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<_>>()
                );
                // let pty = decryptor.decrypt(&y[j]).unwrap();
                // yy[j] = decryptor.decrypt(&y[j]).unwrap();
                assert_eq!(sc1.add(&sc2, encoder).get_value(encoder)[0], yy[j].get_value(encoder)[0]);
            }
            // let challenge: F = transcript.challenge_f(ctx);
            let challenge = oracle.folding_challenges[i].clone();
            res.push(challenge.clone());
            for j in 0..M { 
                // yy.push(Self::uni_extrapolate::<DynamicField>(&base, &pts[j], challenge.clone(), encoder));
                yy[j] = Self::uni_extrapolate::<DynamicField>(&base, &pts[j], challenge.clone(), encoder);
                println!("extrapolate ok.");
            }
        }
        (res, yy.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use arithmetic::{
        field::Field, poly::MultiLinearPoly,
    };
    use rand::thread_rng;
    use seal_fhe::{Asym, BFVEncoder, BFVEvaluator, BfvEncryptionParametersBuilder, Ciphertext, CoefficientModulus, Context, Decryptor, EncryptionParameters, Encryptor, Evaluator, KeyGenerator, PlainModulus, Plaintext};
    use util::random_oracle::RandomOracle;

    use super::Sumcheck;

    type F = Plaintext;
    type Q = Ciphertext;

    const VN: usize = 2;
    const BATCH_SIZE: u64 = 8192;
    const CIPHER_BIT_VEC: &[i32] = &[50, 30, 30, 50, 40];

    fn gen_params_n_ctx() -> (EncryptionParameters, Context) {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(BATCH_SIZE)
            .set_coefficient_modulus(
                CoefficientModulus::create(BATCH_SIZE, CIPHER_BIT_VEC).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(BATCH_SIZE, 20).unwrap())
            .build()
            .unwrap(); 

        let ctx = Context::new(&params, false, seal_fhe::SecurityLevel::TC128).unwrap();
        (params, ctx)
    }

    #[test]
    fn test_ct_multiply() {
        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let relin_keys = key_gen.create_relinearization_keys().unwrap();
        let oracle = RandomOracle::new(VN, 0, &ctx, &params, &key_gen);
        let evaluator = BFVEvaluator::new(&ctx).unwrap();
        let encryptor = Encryptor::<Asym>::new(&ctx, &key_gen.create_public_key()).unwrap();
        let decryptor = Decryptor::new(&ctx, &key_gen.secret_key()).unwrap();

        let a = F::from_int(1 << 5, &encoder);
        let b = F::from_int(1 << 5, &encoder);
        let c = F::from_int(1 << 5, &encoder);
        let d = F::from_int(1 << 5, &encoder);

        let ca = encryptor.encrypt(&a).unwrap();
        let cb = encryptor.encrypt(&b).unwrap();
        let cc = encryptor.encrypt(&c).unwrap();
        let cd = encryptor.encrypt(&d).unwrap();

        let capbbbbbb = ca.mult_plain(&b, &evaluator)
            .mult_plain(&b, &evaluator)
            .mult_plain(&b, &evaluator)
            .mult_plain(&b, &evaluator)
            .mult_plain(&b, &evaluator)
            .mult_plain(&b, &evaluator);

        assert_eq!(decryptor.decrypt(&capbbbbbb).unwrap().get_value(&encoder)[0], 
        a.mult(&b, &encoder).mult(&b, &encoder).mult(&b, &encoder).mult(&b, &encoder).mult(&b, &encoder).mult(&b, &encoder).get_value(&encoder)[0]);
        let capb = evaluator.multiply_plain(&ca, &b).unwrap();
        let capbc = evaluator.multiply_plain(&capb, &c).unwrap();

        let mut cab = evaluator.multiply(&ca, &cb).unwrap();
        let _ = evaluator.relinearize_inplace(&mut cab, &relin_keys);
        let _ = evaluator.mod_switch_to_next_inplace(&mut cab);

        let cabpc = evaluator.multiply_plain(&cab, &c).unwrap();
        let mut cabc = evaluator.multiply(&cab, &cc).unwrap();
        // let _ = evaluator.relinearize_inplace(&mut cabc, &relin_keys);
        // let _ = evaluator.mod_switch_to_next_inplace(&mut cabc);
        let cabcd = evaluator.multiply(&cabc, &cd).unwrap();

        assert_eq!(decryptor.decrypt(&capbc).unwrap().get_value(&encoder)[0], a.mult(&b, &encoder).mult(&c, &encoder).get_value(&encoder)[0]);
        assert_eq!(decryptor.decrypt(&cabpc).unwrap().get_value(&encoder)[0], a.mult(&b, &encoder).mult(&c, &encoder).get_value(&encoder)[0]);
        assert_eq!(decryptor.decrypt(&cabc).unwrap().get_value(&encoder)[0], a.mult(&b, &encoder).mult(&c, &encoder).get_value(&encoder)[0]);
    }

    #[test]
    fn test_sumcheck() {
        let mut rng = thread_rng();
        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let oracle = RandomOracle::new(VN, 0, &ctx, &params, &key_gen);
        let evaluator = BFVEvaluator::new(&ctx).unwrap();
        let encryptor = Encryptor::<Asym>::new(&ctx, &key_gen.create_public_key()).unwrap();
        let decryptor = Decryptor::new(&ctx, &key_gen.secret_key()).unwrap();

        let a = (0..1<<VN)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let b = (0..1<<VN)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let c = (0..1<<VN)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let d = (0..1<<VN)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        // let mut transcript = Transcript::new();
        let (new_point, evals, total_sums) = Sumcheck::prove(
            [a.clone(), b.clone()],
            2,
            |v: [Q; 2]| [v[0].mult(&v[1], &evaluator)],
            // |v: [Q; 4]| [
            //     // evaluator.multiply(&evaluator.add(&evaluator.multiply(&v[0], &v[1]).unwrap(), &v[2]).unwrap(), &v[3]).unwrap(),
            //     v[0].mult(&v[1], &evaluator).add(&v[2], &evaluator).mult(&v[3], &evaluator),
            //     // evaluator.multiply(&evaluator.multiply(&v[2], &v[2]).unwrap(), &v[3]).unwrap()
            //     v[2].mult(&v[2], &evaluator).mult(&v[3], &evaluator)
            // ],
            &ctx,
            &encoder,
            &oracle,
            &evaluator,
            &encryptor,
        );
        let pta = a.iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<_>>();
        let ptb = b.iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<_>>();
        let ptc = c.iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<_>>();
        let ptd = d.iter().map(|x| decryptor.decrypt(x).unwrap()).collect::<Vec<_>>();
        // let y = (0..1<<VN).fold([Q::from_int(0, &encoder, &encryptor), Q::from_int(0, &encoder, &encryptor)], |acc, x| {
        //     [
        //         // acc[0] + (a[x] * b[x] + c[x]) * d[x],
        //         a[x].mult(&b[x], &evaluator).add(&c[x], &evaluator).mult(&d[x], &evaluator).add(&acc[0], &evaluator),
        //         // acc[1] + c[x] * c[x] * d[x],
        //         c[x].mult(&c[x], &evaluator).mult(&d[x], &evaluator).add(&acc[1], &evaluator),
        //     ]
        // });
        let y = (0..1<<VN).fold([Q::from_int(0, &encoder, &encryptor)], |acc, x| {
            [
                a[x].mult(&b[x], &evaluator).add(&acc[0], &evaluator),
                // b[x].add(&acc[1], &evaluator)
            ]
        });
        // let mut proof = transcript.proof;
        // let mut transcript = Transcript::new();
        let (point, y) = Sumcheck::verify(y, 2, VN, total_sums, &params, &ctx, &encoder, &oracle, &evaluator, &encryptor, &decryptor);
        // assert_eq!(
        //     MultiLinearPoly::eval_multilinear_ext(&pta, &point, &encoder)
        //         .mult(&MultiLinearPoly::eval_multilinear_ext(&ptb, &point, &encoder), &encoder)
        //         .add(&MultiLinearPoly::eval_multilinear_ext(&ptc, &point, &encoder), &encoder).mult(&MultiLinearPoly::eval_multilinear_ext(&ptd, &point, &encoder), &encoder),
        //     // (MultiLinearPoly::eval_multilinear_ext(&a, &point, &encoder)
        //     //     * MultiLinearPoly::eval_multilinear_ext(&b, &point, &encoder)
        //     //     + MultiLinearPoly::eval_multilinear_ext(&c, &point, &encoder))
        //     //     * MultiLinearPoly::eval_multilinear_ext(&d, &point, &encoder),
        //     y[0]
        // );
        // assert_eq!(
        //     MultiLinearPoly::eval_multilinear_ext(&ptc, &point, &encoder)
        //         .mult(&MultiLinearPoly::eval_multilinear_ext(&ptc, &point, &encoder), &encoder)
        //         .mult(&MultiLinearPoly::eval_multilinear_ext(&ptd, &point, &encoder), &encoder),
        //     y[1]
        // );
    }
}
