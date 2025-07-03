pub mod circuit;
mod prod_eq_check;
pub mod prover;
// pub mod sumcheck;
pub mod verifier;
pub mod ct_sumcheck;

#[cfg(test)]
mod tests {
    use arithmetic::{
        field::{
            // goldilocks64::{Goldilocks64, Goldilocks64Ext},
            Field,
        },
        mul_group::Radix2Group,
    };
    use poly_commit::{
        // deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier},
        nil::{NilPcProver, NilPcVerifier},
        // shuffle::{ShufflePcProver, ShufflePcVerifier},
    };
    use rand::thread_rng;
    use seal_fhe::{Asym, BFVEncoder, BFVEvaluator, BfvEncryptionParametersBuilder, Ciphertext, CoefficientModulus, Context, Decryptor, EncryptionParameters, Encryptor, Evaluator, KeyGenerator, PlainModulus, Plaintext};
    use util::random_oracle::RandomOracle;

    use crate::{circuit::Circuit, prover::Prover, verifier::Verifier};

    type F = Plaintext;
    type Q = Ciphertext;

    const BATCH_SIZE: u64 = 14;

    fn gen_params_n_ctx() -> (EncryptionParameters, Context) {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(1 << BATCH_SIZE)
            .set_coefficient_modulus(
                CoefficientModulus::create(1 << BATCH_SIZE, &[40; 10]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(1 << BATCH_SIZE, 35).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, seal_fhe::SecurityLevel::TC128).unwrap();

        (params, ctx)
    }

    /**
     * 1. circuits需要用plaintext来encode
     * 2. RadixGroup用来干嘛的？
     * 3. prover & verifier
     */
    #[test]
    fn snark() {
        let nv = 2;
        let num_gates = 1u32 << nv;

        let (params, ctx) = gen_params_n_ctx();
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let relin_key = key_gen.create_relinearization_keys().unwrap();
        let oracle = RandomOracle::new(10, 0, &ctx, &params, &key_gen);
        let evaluator = BFVEvaluator::new(&ctx).unwrap();
        let encryptor = Encryptor::<Asym>::new(&ctx, &key_gen.create_public_key()).unwrap();
        let decryptor = Decryptor::new(&ctx, &key_gen.secret_key()).unwrap();

        let mock_circuit = Circuit {
            permutation: [
                (0..num_gates).map(|x| F::from_int(x.into(), &encoder)).collect(),
                (0..num_gates).map(|x| F::from_int((x + (1 << 29)).into(), &encoder)).collect(),
                (0..num_gates).map(|x| F::from_int((x + (1 << 30)).into(), &encoder)).collect(),
            ], // identical permutation
            selector: (0..num_gates).map(|x| F::from_int((x & 1).into(), &encoder)).collect(),
        };

        // let mut mult_subgroups = vec![Radix2Group::<Goldilocks64>::new(nv + 2)];
        // for i in 1..nv as usize {
        //     mult_subgroups.push(mult_subgroups[i - 1].exp(2));
        // }
        let (pk, vk) = mock_circuit.setup::<NilPcProver, NilPcVerifier>(&(), &(), &params, &ctx);
        let prover = Prover::new(pk, &ctx, &params, &oracle);
        let verifier = Verifier::new(vk, &params, &ctx, &oracle);
        let a = (0..num_gates)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let b = (0..num_gates)
            .map(|_| Q::random_ct(&encoder, &encryptor))
            .collect::<Vec<_>>();
        let c = (0..num_gates)
            .map(|i| {
                let i = i as usize;
                // println!("circuit i: {}", i);
                let s = mock_circuit.selector[i].clone();
                println!("selector {}: {}", i, s.get_value(&encoder)[0]);
                if s.get_value(&encoder)[0] == 0 {
                    evaluator.negate(&a[i].add(&b[i], &evaluator)).unwrap()
                } else {
                    evaluator.negate(&a[i].mult(&b[i], &evaluator)).unwrap()
                }
                // let p1 = a[i].add(&b[i], &evaluator).mult_plain(&F::from_int(1, &encoder).sub(&s, &encoder), &evaluator);
                // let p1 = F::mult(&F::sub(&F::from_int(1, &encoder), &s, &encoder), &F::add(&a[i], &b[i], &encoder), &encoder);
                // let p2 = a[i].mult(&b[i], &evaluator).mult_plain(&s, &evaluator);
                // let p2 = [&a[i], &b[i]].into_iter().fold(s, |x, y| {
                //     F::mult(&x, y, &encoder)
                // });
                // evaluator.negate(&p1.add(&p2, &evaluator)).unwrap()
            })
            .collect();
        let (total_sums, prod_total_sums, prod_transcript, sc_total_sums, proof, ct_proof) = prover.prove(&(), nv as usize, [a, b, c], &params, &ctx, &encoder, &oracle, &encryptor, &evaluator);
        assert!(verifier.verify(&(), nv as usize, proof, ct_proof, total_sums, prod_total_sums, sc_total_sums, prod_transcript, &encoder, &decryptor, &evaluator, &encryptor));
        println!("ok.");
    }
}
