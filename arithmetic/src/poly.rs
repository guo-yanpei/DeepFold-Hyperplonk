use seal_fhe::{Asym, BFVEncoder, BFVEvaluator, Ciphertext, Context, EncryptionParameters, Encryptor, Plaintext};

// use crate::field::Field;

type F = Plaintext;
type Q = Ciphertext;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Definition for an MLE, with an associated type F.
pub struct MultiLinearPoly<'a> {
    pub evals: Vec<F>,
    pub encoder: BFVEncoder<'a>,
}

impl<'a> MultiLinearPoly<'a> {
    pub fn new(evals: Vec<F>, params: &'a EncryptionParameters, ctx: &'a Context) -> MultiLinearPoly<'a> {
        MultiLinearPoly { evals, encoder: BFVEncoder::new(ctx, params).unwrap() }
    }

    pub fn new_eq(r: &Vec<F>, params: &'a EncryptionParameters, ctx: &'a Context) -> MultiLinearPoly<'a> {
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let mut evals = vec![F::from_int(1, &encoder)];
        for b in r.iter().rev() {
            evals = evals
                .iter()
                .flat_map(|prod| {
                    /*[prod * (F::from_int(1, &encoder) - b), prod * b] */
                    let nb = F::sub(&F::from_int(1, &encoder), &b, &encoder);
                    let pnb = F::mult(&prod, &nb, &encoder);
                    let pb = F::mult(&prod, &b, &encoder);
                    [pnb, pb]
                })
                .collect();
        }
        Self::new(evals, params, ctx)
    }

    pub fn eval_eq(r: &Vec<F>, point: &Vec<F>, encoder: &BFVEncoder) -> F {
        assert_eq!(r.len(), point.len());
        let mut res = F::from_int(1, encoder);
        for i in 0..r.len() {
            let tmp = F::mult(&point[i], &r[i], &encoder);
            let delta = [&tmp, &F::neg(&point[i], &encoder), &F::neg(&r[i], &encoder), &F::from_int(1, &encoder)]
                .into_iter().fold(tmp.clone(), |x, y| F::add(&x, &y, &encoder));
            res = F::mult(&res, &delta, &encoder);
            /* res *= tmp + tmp - point[i] - r[i] + F::from_int(1, &encoder); */
        }
        res
    }

    pub fn new_identical(var_num: usize, offset: F, params: &'a EncryptionParameters, ctx: &'a Context) -> MultiLinearPoly<'a> {
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let evals = (0..(1 << var_num)).map(|x| F::add(&F::from_int(x, &encoder), &offset, &encoder)).collect();
        //  MultiLinearPoly {
        //     evals: (0..(1 << var_num)).map(|x| F::from(x) + offset).collect(),
        //  }
        Self::new(evals, params, ctx)
    }

    pub fn eval_identical(point: &Vec<F>, offset: F, encoder: &'a BFVEncoder) -> F {
        let mut res = F::add(&offset, &point[0], encoder);
        let mut t = F::from_int(1, encoder);
        for i in 1..point.len() {
            t = F::add(&t, &t, encoder);
            res = F::add(&res, &F::mult(&point[i], &t, encoder), encoder);
            // res += point[i].mul_base_elem(t);
        }
        res
    }

    pub fn eval_multilinear_ct(evals: &Vec<Q>, point: &Vec<F>, evaluator: &'a BFVEvaluator) -> Q {
        let mut scratch = vec![];
        let mut cur_eval_size = 1 << (point.len() - 1);
        assert_eq!(cur_eval_size << 1, evals.len());
        for i in 0..cur_eval_size {
            let e0 = &evals[i*2];
            let e1 = &evals[i*2+1];
            let mul_elem = e1.sub(&e0, evaluator);
            let push_elem = mul_elem.mult_plain(&point[0], evaluator).add(&e0, evaluator);
            // let push_elem = F::add(&F::mult(&point[0], &mul_elem, encoder), e0, encoder);
            scratch.push(push_elem);
                // point[0]
                //     .mul_base_elem(evals[i * 2 + 1] - evals[i * 2])
                //     .add_base_elem(evals[i * 2]),
        }
        for r in point[1..].iter() {
            cur_eval_size >>= 1;
            for i in 0..cur_eval_size {
                scratch[i] = scratch[i*2+1].sub(&scratch[i*2], evaluator).mult_plain(r, evaluator).add(&scratch[i*2], evaluator);
                // let p2 = F::mult(&F::sub(&scratch[i*2+1], &scratch[i*2], encoder), r, encoder);
                // scratch[i] = F::add(&scratch[i*2], &p2, encoder);
                // scratch[i] = scratch[i * 2] + (scratch[i * 2 + 1] - scratch[i * 2]) * (*r);
            }
        }
        scratch[0].clone()
    }

    pub fn eval_multilinear(evals: &Vec<F>, point: &[F], encoder: &'a BFVEncoder) -> F {
        let mut scratch = vec![];
        let mut cur_eval_size = 1 << (point.len() - 1);
        assert_eq!(cur_eval_size << 1, evals.len());
        for i in 0..cur_eval_size {
            let e0 = &evals[i*2];
            let e1 = &evals[i*2+1];
            let mul_elem = F::sub(e1, e0, encoder);
            let push_elem = F::add(&F::mult(&point[0], &mul_elem, encoder), e0, encoder);
            scratch.push(push_elem);
                // point[0]
                //     .mul_base_elem(evals[i * 2 + 1] - evals[i * 2])
                //     .add_base_elem(evals[i * 2]),
        }
        for r in point[1..].iter() {
            cur_eval_size >>= 1;
            for i in 0..cur_eval_size {
                let p2 = F::mult(&F::sub(&scratch[i*2+1], &scratch[i*2], encoder), r, encoder);
                scratch[i] = F::add(&scratch[i*2], &p2, encoder);
                // scratch[i] = scratch[i * 2] + (scratch[i * 2 + 1] - scratch[i * 2]) * (*r);
            }
        }
        scratch[0].clone()
    }

    pub fn eval_multilinear_ext(evals: &Vec<F>, point: &[F], encoder: &'a BFVEncoder) -> F {
        let mut scratch = evals.to_vec();
        let mut cur_eval_size = evals.len() >> 1;
        assert_eq!(1 << point.len(), evals.len());
        for r in point.iter() {
            for i in 0..cur_eval_size {
                let p2 = F::mult(&F::sub(&scratch[i*2+1], &scratch[i*2], encoder), r, encoder);
                scratch[i] = F::add(&scratch[i*2], &p2, encoder);
            }
            cur_eval_size >>= 1;
        }
        scratch[0].clone()
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use seal_fhe::{
        Asym, BFVEncoder, BfvEncryptionParametersBuilder, CoefficientModulus, Context, Decryptor, EncryptionParameters, Encryptor, KeyGenerator, PlainModulus, Plaintext, SecurityLevel
    };

    // use crate::{field::{bn_254::Bn254F, Field}, poly::F};

    use super::MultiLinearPoly;

    const VN: usize = 2;
    const BATCH_SIZE: u64 = 4096;
    const CIPHER_BIT_VEC: &[i32] = &[40, 30, 30];

    type F = Plaintext;

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
    fn eq() {
        let mut rng = thread_rng();

        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let r = (0..12).map(|_| F::random_pt(&encoder)).collect();
        let eq_r = MultiLinearPoly::new_eq(&r, &params, &ctx);
        let point = (0..12).map(|_| F::random_pt(&encoder)).collect();
        assert_eq!(
            MultiLinearPoly::eval_eq(&r, &point, &encoder),
            MultiLinearPoly::eval_multilinear(&eq_r.evals, &point, &encoder)
        );
        let identical = MultiLinearPoly::new_identical(12, F::from_int(0, &encoder), &params, &ctx);
        let r = (0..12).map(|_| F::random_pt(&encoder)).collect();
        assert_eq!(
            MultiLinearPoly::eval_identical(&r, F::from_int(0, &encoder), &encoder),
            MultiLinearPoly::eval_multilinear_ext(&identical.evals, &r, &encoder)
        );
    }
}
