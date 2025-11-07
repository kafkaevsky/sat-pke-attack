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
    return flatten.from_iterable(
        subset(iterable, r) for r in range(len(iterable) + 1)
    )


def product_simplify(clause, random):

    clause = np.fromiter(clause, dtype=tuple)
    random = np.fromiter(random, dtype=tuple)

    x_array, y_array = np.meshgrid(clause, random)

    product = np.fromiter(zip(x_array.ravel(), y_array.ravel()), dtype=tuple)

    # def unique(t):
    #     return tuple(set(flatten(*t)))
    # product = unique(product)

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

    clauses_file = open(f"data/cipher_{args.count}_dir/clauses_{args.count}.txt", "w")
    print(str(CLAUSES))
    clauses_file.write(str(CLAUSES))
    clauses_file.close()

    cipher = np.empty(0, dtype=object)
    # cipher = np.append(cipher, np.array([1]))
    beta_literals_sets = []

    for a in range(BETA):

        beta_clauses_list = [CLAUSES[r] for r in J_MAP[a]]
        beta_literals_list = [l[0] for l in flatten(*beta_clauses_list)]
        beta_counts_set = set(Counter(beta_literals_list).items())
        
        beta_literals_set = sorted(set(beta_literals_list))
        beta_literals_sets.append(beta_literals_set)

        for i in range(ALPHA):

            ### CLAUSE
            clause = CLAUSES[
                J_MAP[a][i]
            ]  # includes parity: [(x_1, p_1),(x_2, p_2),(x_3, p_3)]
            clause_literals_set = set(
                [l[0] for l in clause]
            )  # excludes parity: {x_1, x_2, x_3}

            clause = cnf_to_neg_anf(clause)

            ### RANDOM
            beta_literals_subset = filter(
                lambda t: t[0] not in clause_literals_set or t[1] >= 2, beta_counts_set
            )
            beta_literals_subset = set(
                [l[0] for l in beta_literals_subset]
            )  # all literals in {c_J(i,b) | b != a}

            anf_all_terms = np.fromiter(distribute(beta_literals_subset), dtype=tuple)

            random = filter(lambda _: secure.choice([True, False]), anf_all_terms)

            ### SUMMAND
            summand = product_simplify(clause, random)


            # summand = map(lambda t: tuple(filter(lambda t: t != 1, t)), summand)
            summand = map(lambda t: tuple(t), summand)


            summand = np.fromiter(summand, dtype=map)

            cipher = np.append(cipher, summand)

    beta_literals_sets = sorted(beta_literals_sets)
    
    beta_sets_file = open(f"data/cipher_{args.count}_dir/beta_literals_sets_{args.count}.txt", "w")
    beta_sets_file.write(str(f"{beta_literals_sets}\n"))
    beta_sets_file.close()

    cipher = set(Counter(cipher).items())
    cipher = filter(lambda t: t[1] % 2 == 1, cipher)
    cipher = list(map(lambda t: t[0], cipher))
    
    #####


    constant_term = int(tuple() in cipher)
    y_term = args.plaintext
    # y_term=0, constant_term=0     =>      do nothing
    # y_term=0, constant_term=1     =>      do nothing
    # y_term=1, constant_term=0     =>      add constant term ()
    # y_term=1, constant_term=1     =>      remove constant term ()

    if y_term == 1 and constant_term == 0:
        cipher.append(tuple())
    if y_term == 1 and constant_term == 1:
        cipher.remove(tuple())
    

    
        
    cipher = np.fromiter([np.sort(t, axis=0) for t in cipher], dtype=object)



    ### SORT

    if args.display:
        cipher = sorted(
            cipher, key=lambda term: [p(term) for p in CIPHER_SORTING_ORDER], reverse=True
        )
        

    ### WRITE TO FILES
    filepath = f"data/cipher_{args.count}_dir/priv_{args.count}.txt"
    with open(filepath, "w") as file:
        file.write(key.PRIVATE_KEY_STRING)

    vlen_dtype = h5py.vlen_dtype(np.dtype("float64"))

    filepath = f"data/cipher_{args.count}_dir/cipher_{args.count}.hdf5"
    with h5py.File(filepath, "w") as file:
        dset = file.create_dataset(
            name="expression", shape=(len(cipher),), dtype=vlen_dtype
        )
        dset[:] = cipher


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Encrypt",
        description="Generates ciphertext file from plaintext based on Sebastian E. Schmittner's SAT-Based Public Key Encryption Scheme",
        epilog="https://eprint.iacr.org/2015/771.pdf",
    )
    parser.add_argument(
        "-y", "--plaintext", choices=[1, 0], type=int, default=1, nargs="?"
    )
    parser.add_argument("-c", "--count", type=int, default=1, nargs="?")
    parser.add_argument("-d", "--display", type=int, default=0, choices=[0,1], nargs="?")
    args = parser.parse_args()

    encrypt()
