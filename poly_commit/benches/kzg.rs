use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::{sync::Arc, test_rng};
use hp::pcs::{
    prelude::{MultilinearKzgPCS, PolynomialCommitmentScheme},
    StructuredReferenceString,
};
use std::time::Instant;

fn main() {
    let size = 20;
    let mut rng = test_rng();
    let uni_params = MultilinearKzgPCS::<Bn254>::gen_srs_for_testing(&mut rng, size).unwrap();
    for nv in 10..size {
        let repetition = if nv < 10 {
            10
        } else if nv < 20 {
            5
        } else {
            2
        };

        let poly = Arc::new(DenseMultilinearExtension::rand(nv, &mut rng));
        let (ck, vk) = uni_params.trim(nv).unwrap();

        let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

        // commit
        let com = {
            let start = Instant::now();
            for _ in 0..repetition {
                let _commit = MultilinearKzgPCS::commit(&ck, &poly).unwrap();
            }

            println!(
                "KZG commit for {} variables: {} ns",
                nv,
                start.elapsed().as_nanos() / repetition as u128
            );

            MultilinearKzgPCS::commit(&ck, &poly).unwrap()
        };

        // open
        let (proof, value) = {
            let start = Instant::now();
            for _ in 0..repetition {
                let _open = MultilinearKzgPCS::open(&ck, &poly, &point).unwrap();
            }

            println!(
                "KZG open for {} variables: {} ns",
                nv,
                start.elapsed().as_nanos() / repetition as u128
            );
            MultilinearKzgPCS::open(&ck, &poly, &point).unwrap()
        };

        // verify
        {
            let start = Instant::now();
            for _ in 0..repetition {
                assert!(MultilinearKzgPCS::verify(&vk, &com, &point, &value, &proof).unwrap());
            }
            println!(
                "KZG verify for {} variables: {} ns",
                nv,
                start.elapsed().as_nanos() / repetition as u128
            );
        }

        println!("====================================");
    }
}