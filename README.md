This is the HyperPlonk PIOP combined with Deepfold PCS code. The HyperPlonk benchmarks are located in `hyperplonk/benches`, which include Deepfold (Basefold) SNARK and PIOP (without PCS). To benchmark a circuit with $2^{n}$ gates, you can set `nv` to $n$.

This repository also includes multilinear KZG. To benchmark HyperPlonk with mKZG for a circuit of $2^n$ gates, you can run the mKZG commitment for a multilinear polynomial of $n$ variates three times and perform one opening. The three commitment operations correspond to the left inputs, right inputs, and outputs for the $2^n$ gates. The single opening is used for the final batched operation. Since multi-thread is used for mKZG by default, to achieve a fair comparison, `RAYON_NUM_THREADS=1` should be added.
We provide a python script to compute performance of KZG SNARK.

**Benchmarking**

- **Deepfold + HyperPlonK**
```bash
cargo bench -p hyperplonk --bench deepfold
```

- **Basefold + HyperPlonK**
```bash
cargo bench -p hyperplonk --bench basefold
```

- **mKZG + HyperPlonK**
```bash
pip install pandas
python bench_kzg.py
```