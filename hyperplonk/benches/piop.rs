use std::time::Instant;

use arithmetic::{
    field::{bn_254::Bn254F, Field},
    mul_group::Radix2Group,
};
use poly_commit::nil::{NilPcProver, NilPcVerifier};
use rand::thread_rng;

use hyperplonk::{circuit::Circuit, prover::Prover, verifier::Verifier};

fn main() {
    bench_mock_circuit::<Bn254F>(20, 1);
}

fn bench_mock_circuit<F: Field>(nv: u32, repetition: usize) {
    let num_gates = 1u32 << nv;
    let mock_circuit = Circuit::<F> {
        permutation: [
            (0..num_gates).map(|x| x.into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 29)).into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 30)).into()).collect(),
        ], // identical permutation
        selector: (0..num_gates).map(|x| (x & 1).into()).collect(),
    };

    let (pk, vk) = mock_circuit.setup::<NilPcProver<_>, NilPcVerifier<_>>(&(), &());
    let prover = Prover { prover_key: pk };
    let verifier = Verifier { verifier_key: vk };
    let a = (0..num_gates)
        .map(|_| F::BaseField::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let b = (0..num_gates)
        .map(|_| F::BaseField::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let c = (0..num_gates)
        .map(|i| {
            let i = i as usize;
            let s = mock_circuit.selector[i];
            -((F::BaseField::one() - s) * (a[i] + b[i]) + s * a[i] * b[i])
        })
        .collect::<Vec<_>>();
    let start = Instant::now();
    for _ in 0..repetition - 1 {
        let proof = prover.prove(&(), nv as usize, [a.clone(), b.clone(), c.clone()]);
    }
    let proof = prover.prove(&(), nv as usize, [a.clone(), b.clone(), c.clone()]);
    println!(
        "proving for 2^{} gates: {} us",
        nv,
        start.elapsed().as_micros() / repetition as u128
    );

    assert!(verifier.verify(&(), nv as usize, proof));
}
