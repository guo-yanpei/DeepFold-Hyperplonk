pub mod circuit;
mod prod_check;
pub mod prover;
mod sumcheck;
pub mod verifier;

#[cfg(test)]
mod tests {
    use arithmetic::field::{
        goldilocks64::{Goldilocks64, Goldilocks64Ext},
        Field,
    };
    use poly_commit::shuffle::{ShufflePcProver, ShufflePcVerifier};
    use rand::thread_rng;

    use crate::{circuit::Circuit, prover::Prover, verifier::Verifier};

    #[test]
    fn snark() {
        let nv = 12u32;
        let num_gates = 1u32 << nv;
        let mock_circuit = Circuit::<Goldilocks64Ext> {
            permutation: [
                (0..num_gates).map(|x| x.into()).collect(),
                (0..num_gates).map(|x| (x + (1 << 29)).into()).collect(),
                (0..num_gates).map(|x| (x + (1 << 30)).into()).collect(),
            ], // identical permutation
            selector: (0..num_gates).map(|x| (x & 1).into()).collect(),
        };
        let (pk, vk) = mock_circuit.setup::<ShufflePcProver<_>, ShufflePcVerifier<_>>(&(), &());
        let prover = Prover { prover_key: pk };
        let verifier = Verifier { verifier_key: vk };
        let a = (0..num_gates)
            .map(|_| Goldilocks64::random(&mut thread_rng()))
            .collect::<Vec<_>>();
        let b = (0..num_gates)
            .map(|_| Goldilocks64::random(&mut thread_rng()))
            .collect::<Vec<_>>();
        let c = (0..num_gates)
            .map(|i| {
                let i = i as usize;
                let s = mock_circuit.selector[i];
                -((Goldilocks64::one() - s) * (a[i] + b[i]) + s * a[i] * b[i])
            })
            .collect();
        let proof = prover.prove(&(), [a, b, c]);
        assert!(verifier.verify(&(), proof));
    }
}
