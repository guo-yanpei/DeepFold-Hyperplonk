use arithmetic::field::Field;
use util::fiat_shamir::Transcript;

pub struct Sumcheck;

impl Sumcheck {
    fn extrapolate<F: Field>() {}

    fn fold_next_domain<F: Field>(poly_evals: &mut Vec<F>, m: usize, challenge: F) {
        for j in 0..m {
            poly_evals[j] =
                poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
        }
        poly_evals.truncate(m / 2)
    }

    pub fn prover<F: Field>(mut evals: Vec<Vec<F>>, transcript: &mut Transcript) -> Vec<F> {
        let n = evals.len();
        let var_num = evals[0].len().ilog2() as usize;
        let mut new_point = vec![];
        for i in 0..var_num {
            let m = 1usize << (var_num - i);
            let sums = (0..m)
                .step_by(2)
                .fold(vec![F::zero(); n + 1], |mut acc, x| {
                    let mut extrapolations = vec![];
                    for j in 0..n {
                        let v_0 = evals[j][x];
                        let v_1 = evals[j][x + 1];
                        let diff = v_1 - v_0;
                        let mut e = vec![v_0, v_1];
                        for k in 1..n {
                            e.push(e[k] + diff);
                        }
                        extrapolations.push(e);
                    }
                    for i in 0..n + 1 {
                        let mut res = F::one();
                        for j in 0..n {
                            res *= extrapolations[j][i];
                        }
                        acc[i] += res;
                    }
                    acc
                });
            for j in sums {
                transcript.append_f(j);
            }
            let challenge = transcript.challenge_f();
            new_point.push(challenge);
            for j in evals.iter_mut() {
                Self::fold_next_domain(j, m / 2, challenge)
            }
        }
        new_point
    }

    pub fn verify() {}
}
