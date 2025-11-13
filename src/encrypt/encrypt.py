import sys
import os
from . import key
import argparse
import secrets
from itertools import chain as flatten, combinations as subset, product as cartesian
from collections import Counter

import numpy as np
import h5py

from parameters import *
from memory_profiler import profile

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
secure = secrets.SystemRandom()


def distribute(iterable):  # from itertools powerset recipe
    return flatten.from_iterable(subset(iterable, r) for r in range(len(iterable) + 1))


def product_simplify(clause, random):
    clause = np.fromiter(clause, dtype=tuple)
    random = np.fromiter(random, dtype=tuple)
    x_array, y_array = np.meshgrid(clause, random)
    product = np.fromiter(zip(x_array.ravel(), y_array.ravel()), dtype=tuple)
    product = [set(flatten(*t)) for t in product]
    return product


def cnf_to_neg_anf(term):
    term = term + [(1,)]
    term = cartesian(*term)
    term = filter(lambda t: 0 not in t, term)  # a*0 = 0
    term = map(lambda t: tuple(filter(lambda t: t != 1, t)), term)  # a*1 = a
    term = map(lambda t: tuple(set(t)), term)  # a*a = a
    return term


@profile
def encrypt():
    J_MAP = [secure.sample(range(1, M), ALPHA) for _ in range(BETA)]
    CLAUSES = key.generate_clause_list()

    cipher = np.empty(0, dtype=object)
    beta_literals_sets = []

    for a in range(BETA):

        beta_clauses_list = [CLAUSES[r] for r in J_MAP[a]]
        beta_literals_list = [l[0] for l in flatten(*beta_clauses_list)]
        beta_counts_set = set(Counter(beta_literals_list).items())
        beta_literals_set = sorted(set(beta_literals_list))
        beta_literals_sets.append(beta_literals_set)

        for i in range(ALPHA):

            ### clause_i
            clause = CLAUSES[J_MAP[a][i]]
            clause_literals_set = set([l[0] for l in clause])
            clause = cnf_to_neg_anf(clause)

            ### random_i
            beta_literals_subset = filter(
                lambda t: t[0] not in clause_literals_set or t[1] >= 2, beta_counts_set
            )
            beta_literals_subset = set([l[0] for l in beta_literals_subset])
            anf_all_terms = np.fromiter(distribute(beta_literals_subset), dtype=tuple)
            random = filter(lambda _: secure.choice([True, False]), anf_all_terms)

            ### clause_i * random_i
            summand = product_simplify(clause, random)
            summand = map(lambda t: tuple(t), summand)
            summand = np.fromiter(summand, dtype=map)
            cipher = np.append(cipher, summand)

    beta_literals_sets = sorted(beta_literals_sets)

    cipher = set(Counter(cipher).items())
    cipher = filter(lambda t: t[1] % 2 == 1, cipher)
    cipher = list(map(lambda t: t[0], cipher))

    #####

    constant_term = int(tuple() in cipher)
    y_term = args.plaintext

    # y_term=0, constant_term=0     =>      do nothing
    # y_term=0, constant_term=1     =>      do nothing
    # y_term=1, constant_term=0     =>      add constant term 1 aka ()
    # y_term=1, constant_term=1     =>      remove constant term 1 aka ()
    if y_term == 1 and constant_term == 0:
        cipher.append(tuple())
    if y_term == 1 and constant_term == 1:
        cipher.remove(tuple())

    cipher = np.fromiter([np.sort(t, axis=0) for t in cipher], dtype=object)

    ### clauses_n__txt AND # clauses_n__hdf5
    if LEAVE_CLAUSES_UNSORTED:
        cipher = sorted(
            cipher,
            key=lambda term: np.array([p(term) for p in CIPHERTEXT_SORTING_ORDER]),
            reverse=True,
        )

    ### private_key_n__txt
    f = open(f"data/cipher_{args.n}_dir/private_key_{args.n}.txt", "w")
    f.write(str(f"{key.PRIVATE_KEY_STRING}\n"))
    f.close()

    ### beta_literals_sets_n__txt
    if INCLUDE_BETA_LITERALS_SETS_N__TXT:
        f = open(f"data/cipher_{args.n}_dir/beta_literals_sets_{args.n}.txt", "w")
        f.write(str(f"{beta_literals_sets}\n"))
        f.close()

    ### clauses_n__txt
    f = open(f"data/cipher_{args.n}_dir/clauses_{args.n}.txt", "w")
    f.write(str(CLAUSES))
    f.close()

    ### clauses_n__hdf5
    vlen_dtype = h5py.vlen_dtype(np.dtype("float64"))
    ciphertext_n__hdf5_file = f"data/cipher_{args.n}_dir/ciphertext_{args.n}.hdf5"
    with h5py.File(ciphertext_n__hdf5_file, "w") as f:
        dset = f.create_dataset(
            name="expression", shape=(len(cipher),), dtype=vlen_dtype
        )
        dset[:] = cipher


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Encrypt",
        description="Generates ciphertext file from plaintext based on Sebastian E. Schmittner's SAT-Based Public Key Encryption Scheme",
        epilog="https://eprint.iacr.org/2015/771.pdf",
    )
    parser.add_argument("-n", type=int)
    parser.add_argument("-y", "--plaintext", choices=[1, 0], type=int)
    args = parser.parse_args()

    encrypt()
