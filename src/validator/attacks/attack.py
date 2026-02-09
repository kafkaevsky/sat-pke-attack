try:
    import retrieve_rs
except Exception:
    retrieve_rs = None
import argparse
import h5py
from ..parameters import *
import ast


def _linearization(ciphertext_file, public_key_file):

    if "ciphertext" not in ciphertext_file:
        raise KeyError()

    ciphertext_set = {tuple(m) for m in ciphertext_file["ciphertext"]}


def main():

    parser = argparse.ArgumentParser(prog="Attack")
    parser.add_argument("i", type=int)
    args = parser.parse_args()

    DIR = f"tests/c_{args.i}"

    with h5py.File(f"{DIR}/ciphertext_{args.i}.hdf5", "r") as CIPHERTEXT_FILE:
        with open(f"{DIR}/public_key_{args.i}.txt", "r") as PUBLIC_KEY_FILE:
            if retrieve_rs is None:
                raise RuntimeError(
                    """`retrieve_rs` module not built. 
                    Run `source venv/bin/activate && maturin develop --manifest-path src/validator/attacks/retrieve_rs/Cargo.toml`"""
                )

            # ct = [[2, 3, 4], [6], [5, 5], [7, 3]]
            # pk = [[(1, 1), (2, 0), (3, 1)], [(2, 0), (3, 1), (4, 0)], [(4, 0), (5, 1), (6, 1)], [(6, 1), (1, 1), (3, 0)]]
            # n = 10

            ct = list({tuple(m) for m in CIPHERTEXT_FILE["ciphertext"]})
            pk = [tuple(c) for c in ast.literal_eval(PUBLIC_KEY_FILE.read())]
            n = N

            res = retrieve_rs.retrieve(ct, pk, n)
            for x in res:
                print(x.clause, x.vars)
            # y = _linearization(CIPHERTEXT_FILE, CLAUSES_FILE)
            # print(y)


if __name__ == "__main__":
    main()
