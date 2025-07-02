// pub mod circuit;
// mod prod_eq_check;
// pub mod prover;
// mod sumcheck;
// pub mod verifier;
pub mod ct_sumcheck;

// #[cfg(test)]
// mod tests {
//     use arithmetic::{
//         field::{
//             // goldilocks64::{Goldilocks64, Goldilocks64Ext},
//             Field,
//         },
//         mul_group::Radix2Group,
//     };
//     use poly_commit::{
//         // deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier},
//         nil::{NilPcProver, NilPcVerifier},
//         // shuffle::{ShufflePcProver, ShufflePcVerifier},
//     };
//     use rand::thread_rng;
//     use seal_fhe::{BFVEncoder, BfvEncryptionParametersBuilder, CoefficientModulus, Context, EncryptionParameters, KeyGenerator, PlainModulus, Plaintext};
//     use util::random_oracle::RandomOracle;

//     use crate::{circuit::Circuit, prover::Prover, verifier::Verifier};

//     type F = Plaintext;

//     fn gen_params_n_ctx() -> (EncryptionParameters, Context) {
//         let params = BfvEncryptionParametersBuilder::new()
//             .set_poly_modulus_degree(8192)
//             .set_coefficient_modulus(
//                 CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
//             )
//             .set_plain_modulus(PlainModulus::batching(8192, 40).unwrap())
//             .build()
//             .unwrap();

//         let ctx = Context::new(&params, false, seal_fhe::SecurityLevel::TC128).unwrap();

//         (params, ctx)
//     }

//     /**
//      * 1. circuits需要用plaintext来encode
//      * 2. RadixGroup用来干嘛的？
//      * 3. prover & verifier
//      */
//     #[test]
//     fn snark() {
//         let nv = 2;
//         let num_gates = 1u32 << nv;

//         let (params, ctx) = gen_params_n_ctx();
//         let encoder = BFVEncoder::new(&ctx, &params).unwrap();
//         let key_gen = KeyGenerator::new(&ctx).unwrap();
//         let oracle = RandomOracle::new(10, 1, &ctx, &params, &key_gen);

//         let mock_circuit = Circuit {
//             permutation: [
//                 (0..num_gates).map(|x| F::from_int(x.into(), &encoder)).collect(),
//                 (0..num_gates).map(|x| F::from_int((x + (1 << 29)).into(), &encoder)).collect(),
//                 (0..num_gates).map(|x| F::from_int((x + (1 << 30)).into(), &encoder)).collect(),
//             ], // identical permutation
//             selector: (0..num_gates).map(|x| F::from_int((x & 1).into(), &encoder)).collect(),
//         };

//         // let mut mult_subgroups = vec![Radix2Group::<Goldilocks64>::new(nv + 2)];
//         // for i in 1..nv as usize {
//         //     mult_subgroups.push(mult_subgroups[i - 1].exp(2));
//         // }
//         let (pk, vk) = mock_circuit.setup::<NilPcProver, NilPcVerifier>(&(), &(), &params, &ctx);
//         let prover = Prover::new(pk, &ctx, &params, &oracle);
//         let verifier = Verifier::new(vk, &params, &ctx, &oracle);
//         let a = (0..num_gates)
//             .map(|_| F::random_pt(&encoder))
//             .collect::<Vec<_>>();
//         let b = (0..num_gates)
//             .map(|_| F::random_pt(&encoder))
//             .collect::<Vec<_>>();
//         let c = (0..num_gates)
//             .map(|i| {
//                 let i = i as usize;
//                 let s = mock_circuit.selector[i].clone();
//                 let p1 = F::mult(&F::sub(&F::from_int(1, &encoder), &s, &encoder), &F::add(&a[i], &b[i], &encoder), &encoder);
//                 let p2 = [&a[i], &b[i]].into_iter().fold(s, |x, y| {
//                     F::mult(&x, y, &encoder)
//                 });
//                 F::neg(&F::add(&p1, &p2, &encoder), &encoder)
//             })
//             .collect();
//         let (total_sums, prod_total_sums, prod_transcript, sc_total_sums, proof) = prover.prove(&(), nv as usize, [a, b, c], &params, &ctx, &encoder, &oracle);
//         assert!(verifier.verify(&(), nv as usize, proof, total_sums, prod_total_sums, sc_total_sums, prod_transcript));
//         println!("ok.");
//     }
// }
