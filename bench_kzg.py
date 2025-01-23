import os
import pandas as pd

os.system("cargo bench -p hyperplonk --bench piop")
os.system("RAYON_NUM_THREADS=1 cargo bench -p poly_commit --bench kzg")
data1 = pd.read_csv("hyperplonk/piop.csv")
data2 = pd.read_csv("poly_commit/mkzg.csv")

piop_row = data1[data1["nv"] == 15]
kzg_row = data2[data2["nv"] == 15]
print(
    "prover time: ",
    piop_row["prover_time"].values[0]
    + kzg_row["commit_time"].values[0] * 3
    + kzg_row["open_time"].values[0],
)

print(
    "verifier time: ",
    piop_row["verifier_time"].values[0]
    + kzg_row["verifier_time"].values[0],
)

print(
    "proof size: ",
    piop_row["proof_size"].values[0]
    + kzg_row["proof_size"].values[0]
)
