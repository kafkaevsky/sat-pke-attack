try:
    import retrieve_rs
except Exception:
    retrieve_rs = None
import argparse
import h5py
import numpy as np
from ..parameters import *
from ..helpers import *
import ast
from collections import defaultdict


def _linearization(ciphertext_file, t_prime):

    if "ciphertext" not in ciphertext_file:
        raise KeyError()

    ciphertext_set = {tuple((int(x) for x in m)) for m in ciphertext_file["ciphertext"]}

    def clause_from_element(element):
        if hasattr(element, "clause"):
            return list(element.clause)
        return list(element[1])

    term_to_mask = {}
    coefficient_count = 0

    for t_prime_i in t_prime:

        t_prime_i_incl_sign = [clause_from_element(c) for c in t_prime_i]

        C = [cnf_to_neg_anf(list(c)) for c in t_prime_i_incl_sign]
        for i, C_i in enumerate(C):

            other_clauses = t_prime_i_incl_sign[:i] + t_prime_i_incl_sign[i + 1 :]

            R_vars = {var for clause in other_clauses for (var, _) in clause}
            R_vars_list = list(R_vars)

            n_subsets = 1 << len(R_vars_list)
            start_col = coefficient_count
            coefficient_count += n_subsets

            for subset_i, R_term in enumerate(distribute(R_vars_list)):
                col = start_col + subset_i
                col_bit = 1 << col

                if R_term:
                    R_set = set(int(x) for x in R_term)
                    for C_term in C_i:
                        if C_term:
                            literals = tuple(sorted(R_set.union(C_term)))
                        else:
                            literals = tuple(sorted(R_set))
                        term_to_mask[literals] = term_to_mask.get(literals, 0) ^ col_bit
                else:
                    for C_term in C_i:
                        literals = tuple(int(x) for x in C_term)
                        term_to_mask[literals] = term_to_mask.get(literals, 0) ^ col_bit
    term_list = list(term_to_mask.keys())
    term_to_row = {term: i for i, term in enumerate(term_list)}

    b = np.zeros(len(term_list), dtype=np.uint8)
    for i, term in enumerate(term_list):
        b[i] = 1 if term in ciphertext_set else 0

    def _rank_gf2_bitrows(rows):
        basis = {}
        for r in rows:
            x = r
            while x:
                pivot = x.bit_length() - 1
                if pivot in basis:
                    x ^= basis[pivot]
                else:
                    basis[pivot] = x
                    break
        return len(basis)

    def _is_consistent_bitrows(row_masks, b_vec, ncols):
        rank_a = _rank_gf2_bitrows(row_masks)
        aug_bit = 1 << ncols
        augmented_rows = []
        for r, b_i in zip(row_masks, b_vec):
            augmented_rows.append(r ^ (aug_bit if b_i else 0))
        rank_aug = _rank_gf2_bitrows(augmented_rows)
        return rank_a == rank_aug

    row_masks = [term_to_mask[t] for t in term_list]

    b0 = b.copy()
    b1 = b.copy()

    constant_row = term_to_row.get(tuple())
    if constant_row is None:
        y = int(tuple() in ciphertext_set)
        return y, "ok0" if y == 0 else "ok1"

    b1[constant_row] ^= 1

    ok0 = _is_consistent_bitrows(row_masks, b0, coefficient_count)
    ok1 = _is_consistent_bitrows(row_masks, b1, coefficient_count)

    if ok0 and ok1:
        return None, "both"
    if ok0 and not ok1:
        return 0, "ok0"
    if ok1 and not ok0:
        return 1, "ok1"
    return None, "neither"


def attack(args):

    DIR = f"tests/c_{args.i}"

    with h5py.File(f"{DIR}/ciphertext_{args.i}.hdf5", "r") as CIPHERTEXT_FILE:
        with open(f"{DIR}/public_key_{args.i}.txt", "r") as PUBLIC_KEY_FILE:
            if retrieve_rs is None:
                raise RuntimeError(
                    """`retrieve_rs` module not built. 
                    Run `source venv/bin/activate && maturin develop --manifest-path src/validator/attacks/retrieve_rs/Cargo.toml`"""
                )

            ct = list({tuple(m) for m in CIPHERTEXT_FILE["ciphertext"]})
            pk = [tuple(c) for c in ast.literal_eval(PUBLIC_KEY_FILE.read())]
            n = N

            res = retrieve_rs.retrieve(ct, pk, n, 100, 30)
            y, status = _linearization(CIPHERTEXT_FILE, res)
            if status == "neither":
                res = retrieve_rs.retrieve(ct, pk, n, 1000, 300)
                y, status = _linearization(CIPHERTEXT_FILE, res)
            if status == "both":
                raise RuntimeError(
                    "message assumptions were both solvable => there is a bug with the code"
                )

            return y


def main():

    parser = argparse.ArgumentParser(prog="Attack")
    parser.add_argument("i", type=int)
    args = parser.parse_args()
    print(attack(args))


if __name__ == "__main__":
    main()
