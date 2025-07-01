use arithmetic::field::{batch_inverse, dynamic_field::DynamicField, Field};
use seal_fhe::{BFVEncoder, Context, EncryptionParameters, Plaintext};
use util::{fiat_shamir::{Proof, Transcript}, random_oracle::RandomOracle};

pub struct Sumcheck;

type F = Plaintext;

type T = DynamicField;

impl<'a> Sumcheck {
    fn fold_next_domain(poly_evals: &mut Vec<F>, m: usize, challenge: F, encoder: &'a BFVEncoder) {
        for j in 0..m {
            poly_evals[j] = F::add(&poly_evals[j*2], &F::mult(&F::sub(&poly_evals[j*2+1], &poly_evals[j*2], encoder), &challenge, encoder), encoder);
                // poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
        }
        poly_evals.truncate(m)
    }

    // N: 5 (l, r, o, selector, eq; degree of polynomial+1); M: 1
    pub fn prove<const N: usize, const M: usize, FUNC: Fn([F; N]) -> [F; M]>(
        mut evals: [Vec<F>; N],
        degree: usize,
        // transcript: &mut Transcript,
        f: FUNC,
        ctx: &'a Context,
        encoder: &BFVEncoder,
        oracle: &RandomOracle
    ) -> (Vec<F>, [F; N], Vec<[Vec<Plaintext>; M]>) {
        let var_num = evals[0].len().ilog2() as usize;
        println!("var num: {}, prover M: {}", var_num, M);
        let mut new_point = vec![];
        let mut total_sums = vec![];
        for i in 0..var_num {
            let m = 1usize << (var_num - i);
            let sums = (0..m).step_by(2).fold(
                [0; M].map(|_| vec![F::from_int(0, encoder); degree + 1]),
                |mut acc, x| {
                    let mut extrapolations = vec![];
                    for j in 0..N {
                        let v_0 = evals[j][x].clone();
                        let v_1 = evals[j][x + 1].clone();
                        let diff = F::sub(&v_1, &v_0, encoder);
                        let mut e = vec![v_0.clone(), v_1.clone()];
                        for k in 1..degree {
                            e.push(F::add(&e[k], &diff, encoder));
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
                            acc[k][j] = F::add(&acc[k][j], &tmp[k], encoder);
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
                Self::fold_next_domain(j, m / 2, challenge.clone(), encoder)
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
            println!("prod modulus: {}", prod.get_modulus());
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
        mut y: [F; M],
        degree: usize,
        var_num: usize,
        total_sums: Vec<[Vec<F>; M]>,
        // transcript: &mut Transcript,
        // proof: &mut Proof,
        params: &'a EncryptionParameters,
        ctx: &'a Context,
        encoder: &BFVEncoder,
        oracle: &RandomOracle,
    ) -> (Vec<F>, [F; M]) {
        let mut res = vec![];
        let modulus = params.get_plain_modulus().value();
        println!("modulus: {}", modulus);
        let base = Self::init_base(degree, modulus);
        println!("init base ok.");
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
            for j in 0..M {
                println!("j: {}", j);
                assert_eq!(sums[j][0].add(&sums[j][1], encoder), y[j]);
            }
            // let challenge: F = transcript.challenge_f(ctx);
            let challenge = oracle.folding_challenges[i].clone();
            res.push(challenge.clone());
            for j in 0..M {
                y[j] = Self::uni_extrapolate::<DynamicField>(&base, &sums[j], challenge.clone(), encoder);
                println!("extrapolate ok.");
            }
        }
        (res, y)
    }
}

#[cfg(test)]
mod tests {
    use arithmetic::{
        field::Field, poly::MultiLinearPoly,
    };
    use rand::thread_rng;
    use seal_fhe::{BFVEncoder, BfvEncryptionParametersBuilder, CoefficientModulus, Context, EncryptionParameters, KeyGenerator, PlainModulus, Plaintext};
    use util::random_oracle::RandomOracle;

    use super::Sumcheck;

    type F = Plaintext;

    const VN: usize = 5;
    const BATCH_SIZE: u64 = 4096;
    const CIPHER_BIT_VEC: &[i32] = &[40, 30, 30];

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
    fn test_sumcheck() {
        let mut rng = thread_rng();
        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let oracle = RandomOracle::new(VN, 0, &ctx, &params, &key_gen);

        let a = (0..1<<VN)
            .map(|_| F::random_pt(&encoder))
            .collect::<Vec<_>>();
        let b = (0..1<<VN)
            .map(|_| F::random_pt(&encoder))
            .collect::<Vec<_>>();
        let c = (0..1<<VN)
            .map(|_| F::random_pt(&encoder))
            .collect::<Vec<_>>();
        let d = (0..1<<VN)
            .map(|_| F::random_pt(&encoder))
            .collect::<Vec<_>>();
        // let mut transcript = Transcript::new();
        let (new_point, evals, total_sums) = Sumcheck::prove(
            [a.clone(), b.clone(), c.clone(), d.clone()],
            3,
            // |v: [F; 4]| [(v[0] * v[1] + v[2]) * v[3], v[2] * v[2] * v[3]],
            |v: [F; 4]| [
                v[0].mult(&v[1], &encoder).add(&v[2], &encoder).mult(&v[3], &encoder),
                v[2].mult(&v[2], &encoder).mult(&v[3], &encoder)
            ],
            &ctx,
            &encoder,
            &oracle,
        );
        let y = (0..1<<VN).fold([F::from_int(0, &encoder), F::from_int(0, &encoder)], |acc, x| {
            [
                // acc[0] + (a[x] * b[x] + c[x]) * d[x],
                a[x].mult(&b[x], &encoder).add(&c[x], &encoder).mult(&d[x], &encoder).add(&acc[0], &encoder),
                // acc[1] + c[x] * c[x] * d[x],
                c[x].mult(&c[x], &encoder).mult(&d[x], &encoder).add(&acc[1], &encoder),
            ]
        });
        // let mut proof = transcript.proof;
        // let mut transcript = Transcript::new();
        let (point, y) = Sumcheck::verify(y, 3, VN, total_sums, &params, &ctx, &encoder, &oracle);
        assert_eq!(
            MultiLinearPoly::eval_multilinear_ext(&a, &point, &encoder)
                .mult(&MultiLinearPoly::eval_multilinear_ext(&b, &point, &encoder), &encoder)
                .add(&MultiLinearPoly::eval_multilinear_ext(&c, &point, &encoder), &encoder).mult(&MultiLinearPoly::eval_multilinear_ext(&d, &point, &encoder), &encoder),
            // (MultiLinearPoly::eval_multilinear_ext(&a, &point, &encoder)
            //     * MultiLinearPoly::eval_multilinear_ext(&b, &point, &encoder)
            //     + MultiLinearPoly::eval_multilinear_ext(&c, &point, &encoder))
            //     * MultiLinearPoly::eval_multilinear_ext(&d, &point, &encoder),
            y[0]
        );
        assert_eq!(
            MultiLinearPoly::eval_multilinear_ext(&c, &point, &encoder)
                .mult(&MultiLinearPoly::eval_multilinear_ext(&c, &point, &encoder), &encoder)
                .mult(&MultiLinearPoly::eval_multilinear_ext(&d, &point, &encoder), &encoder),
            y[1]
        );
    }
}
