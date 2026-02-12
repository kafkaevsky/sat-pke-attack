import sys
import os
from . import key
import argparse
import secrets
from itertools import chain as flatten
from collections import Counter
import numpy as np
import h5py
from ..parameters import *
from ..helpers import *

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
secure = secrets.SystemRandom()


def generate_j_map():
    """Generate J : {1, . . . , α} × {1, . . . , β} → {1, . . . , m}."""
    # if CONDITIONS_B_C:
    #     if ALPHA != M:
    #         raise ValueError("ALPHA must equal M for conditions B/C")
        
    indices = list(range(M))
    secure.shuffle(indices)
    
    return [
        [indices[(i + a - 1) % M] for a in range(1, BETA + 1)]
        for i in range(1, ALPHA + 1)
    ]
    # return []


def _encrypt(args):
    PUBLIC_KEY = key.generate_clause_list()
    J_MAP = generate_j_map()

    ciphertext = np.empty(0, dtype=object)
    beta_literals_sets = []

    for a in range(ALPHA):
        beta_clauses_list = [PUBLIC_KEY[r] for r in J_MAP[a]]
        beta_literals_list = [l[0] for l in flatten(*beta_clauses_list)]
        beta_counts_set = set(Counter(beta_literals_list).items())
        beta_literals_set = sorted(set(beta_literals_list))
        beta_literals_sets.append(beta_literals_set)

        for i in range(BETA):

            clause = PUBLIC_KEY[J_MAP[a][i]]
            clause_literals_set = set(l[0] for l in clause)
            clause = cnf_to_neg_anf(clause)
            beta_literals_subset = filter(
                lambda t: t[0] not in clause_literals_set or t[1] >= 2, beta_counts_set
            )
            beta_literals_subset = set([l[0] for l in beta_literals_subset])
            anf_all_terms = np.fromiter(distribute(beta_literals_subset), dtype=tuple)
            random = filter(lambda _: secure.choice([True, False]), anf_all_terms)

            summand = product_simplify(clause, random)
            summand = np.fromiter(map(lambda t: tuple(t), summand), dtype=map)
            ciphertext = np.append(ciphertext, summand)

    beta_literals_sets = sorted(beta_literals_sets)

    ciphertext = np.fromiter(
        [tuple(np.sort(t, axis=0)) for t in ciphertext], dtype=object
    )
    ciphertext = set(Counter(ciphertext).items())
    ciphertext = filter(lambda t: t[1] % 2 == 1, ciphertext)
    ciphertext = list(map(lambda t: t[0], ciphertext))
    constant_term = int(ciphertext.count(tuple()))
    y_term = args.plaintext

    print("constant term", constant_term)

    # y_term=0, constant_term=0     =>      do nothing
    # y_term=0, constant_term=1     =>      do nothing
    # y_term=1, constant_term=0     =>      add constant term 1 aka ()
    # y_term=1, constant_term=1     =>      remove constant term 1 aka ()
    if y_term == 1 and constant_term == 0:
        ciphertext.append(tuple())
    elif y_term == 1 and constant_term == 1:
        ciphertext.remove(tuple())

    if LEAVE_MONOMIALS_UNSORTED:
        ciphertext = sorted(
            ciphertext,
            key=lambda term: np.array([p(term) for p in [len]]),
            reverse=True,
        )


    PUBLIC_KEY_FILEPATH = f"tests/c_{args.i}/public_key_{args.i}.txt"
    PRIVATE_KEY_FILEPATH = f"tests/c_{args.i}/private_key_{args.i}.txt"
    BETA_LITERALS_SETS_FILEPATH = f"tests/c_{args.i}/beta_literals_sets_{args.i}.txt"
    CIPHERTEXT_FILEPATH = f"tests/c_{args.i}/ciphertext_{args.i}.hdf5"

    with open(PRIVATE_KEY_FILEPATH, "w") as f:
        f.write(str(f"{key.PRIVATE_KEY_STRING}\n"))

    with open(BETA_LITERALS_SETS_FILEPATH, "w") as f:
        f.write(str(f"{beta_literals_sets}\n"))

    with open(PUBLIC_KEY_FILEPATH, "w") as f:
        f.write(str(PUBLIC_KEY))

    with h5py.File(CIPHERTEXT_FILEPATH, "w") as f:
        vlen_dtype = h5py.vlen_dtype(np.dtype("int64"))
        dset = f.create_dataset(
            name="ciphertext", shape=(len(ciphertext),), dtype=vlen_dtype
        )
        dset[:] = ciphertext


def main():
    parser = argparse.ArgumentParser(prog="Encrypt")
    parser.add_argument("-i", type=int)
    parser.add_argument("-y", "--plaintext", choices=[1, 0], type=int)
    args = parser.parse_args()
    _encrypt(args)


if __name__ == "__main__":
    main()
