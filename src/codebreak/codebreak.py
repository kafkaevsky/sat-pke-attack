import argparse
import os
import sys
import ast
from collections import defaultdict, Counter

from itertools import chain as flatten, combinations as subset, product as cartesian
import galois
import h5py
import numpy as np


from src.encrypt.encrypt import cnf_to_neg_anf, distribute
from parameters import *

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


MAX_DIFF_PCT = 0.5


class Coefficient:
    def __init__(self, v):
        self.value = v

    def __repr__(self):
        return f"Coefficient(v={self.value})"

    def __eq__(self, other):
        if not isinstance(other, Coefficient):
            raise NotImplementedError
        return self.value == other.value


def recover_beta_literals(cipher_n__hdf5_file):
    if "expression" in cipher_n__hdf5_file:

        ciphertext = cipher_n__hdf5_file["expression"]
        ciphertext = np.array(ciphertext[:])
        ciphertext = map(tuple, ciphertext)

        lengths = map(len, ciphertext)

        ciphertext = zip(ciphertext, lengths)
        ciphertext, _ = zip(*filter(lambda x: x[1] > TERM_LENGTH_CUTOFF, ciphertext))
        ciphertext = set(ciphertext)

        groups = []

        while len(groups) < BETA:

            largest = max(ciphertext, key=len)
            group = set(largest)
            ciphertext.remove(largest)

            while True:

                closeness = map(lambda x: (x, len(group.difference(x))), ciphertext)
                closest = min(closeness, key=lambda x: x[1])

                max_diff = math.floor(MAX_DIFF_PCT * len(group))

                if closest[1] <= max_diff:
                    group = group.union(closest[0])
                    ciphertext.remove(closest[0])
                else:
                    groups.append(group)
                    group = set()
                    break

        beta_literals_sets = []
        for s in groups:
            beta_literals_sets.append(sorted([int(l) for l in s]))
        return sorted(beta_literals_sets)


def recover_plaintext(
    cipher_n__hdf5_file, clauses_n__txt_file, beta_literals_sets_n__txt_file
):

    beta_literals_sets = recover_beta_literals(cipher_n__hdf5_file)

    clauses = clauses_n__txt_file.read()
    all_clauses = ast.literal_eval(clauses)
    print("all clauses", all_clauses)

    print("the beta literals sets found by recover_beta_literals():")
    for x in beta_literals_sets:
        print([int(l) for l in x])

    print("the real beta literals sets:")
    real_beta_literals_sets = ast.literal_eval(beta_literals_sets_n__txt_file.read())
    for x in real_beta_literals_sets:
        print(x)

    a_terms = defaultdict(list)

    coefficient_count = 0

    for beta_literals_set in beta_literals_sets:

        possible_clauses = np.fromiter(
            filter(
                lambda c: all(map(lambda l: l in beta_literals_set, list(zip(*c))[0])),
                all_clauses,
            ),
            dtype=list,
        )

        if len(possible_clauses) < ALPHA:
            raise ValueError(f"<{ALPHA} clauses found")

        v__cnf_to_neg_anf = np.vectorize(cnf_to_neg_anf)
        C = v__cnf_to_neg_anf(possible_clauses)
        for i, C_i in enumerate(C):
            #####
            C_i = np.fromiter(C_i, dtype=object)

            #####

            C_minus_C_i = list(possible_clauses[:i]) + list(possible_clauses[i+1:])
            R_i_literals_set = list(set([l[0] for l in flatten(*C_minus_C_i)]))


            R_terms = np.fromiter(distribute(R_i_literals_set), dtype=object)
            n = len(R_terms)
            coefficient_count += n

            R_i_terms = R_terms
            R_i_coefficients = np.fromiter(map(
                lambda i: Coefficient(i),
                range(coefficient_count - n, coefficient_count),
            ), dtype=object)
            R_i = np.fromiter(zip(R_i_coefficients, R_i_terms), dtype=object)
            # print(R_i_terms)
            # print(R_i_coefficients)
            # print(R_i)

            #####
            unformatted_C_iR_i = np.fromiter(cartesian(R_i, C_i), dtype=object)
            C_iR_i = []

            for term in unformatted_C_iR_i:
                # print(term)

                coefficient = term[0][0]
                literals = tuple(sorted([int(x) for x in set(term[0][1] + term[1])]))
                full_term = (coefficient, literals)
                C_iR_i.append(full_term)

            for term in C_iR_i:

                coefficient = term[0]
                literals = term[1]
                a_terms[literals] = a_terms[literals] + [coefficient]
            # print(a_terms)

    def clause_vector(coefficients, cols):
        v = np.zeros(cols)
        for c in coefficients:
            v[c.value] = 1
        return v

    cipher = cipher_n__hdf5_file["expression"][:]
    cipher = map(lambda x: tuple([int(l) for l in x]), cipher)
    rearranged_cipher = Counter(list(cipher))
    simplified_cipher = set(
        filter(lambda x: rearranged_cipher[x] % 2 == 1, rearranged_cipher)
    )

    if len(simplified_cipher - set(a_terms.keys())) > 0:
        # print(simplified_cipher - set(a_terms.keys()))
        raise ValueError("Uh oh, something went wrong with the codebreaking")

    rows = len(a_terms.keys())
    cols = coefficient_count
    print(rows)
    print(cols)

    # # system = defaultdict(tuple)
    # for x in a_terms:
    #      #print(x, a_terms[x])

    a = np.zeros((rows, cols), dtype=np.int64)
    b = np.zeros(rows, dtype=np.int64)

    for i, term in enumerate(a_terms):
        a[i] = clause_vector(a_terms[term], cols)
        b[i] = int(term in simplified_cipher)
        if sum(a[i]) == 0 and b[i] == 1:
            # print(term, a[i], b[i])
            raise ValueError
        # system[term] = {
        #     "a_i": clause_vector(a_terms[term], cols),
        #     "b_i": int(term in simplified_cipher)
        # }


    GF = galois.GF(2)
    a = GF(a)
    b = GF(b)

    print(f"\na:\n{a}\nb:\n{b}")

    rank_a = np.linalg.matrix_rank(a)
    augmented_matrix = np.hstack((a, b.reshape(-1, 1)))
    rank_augmented = np.linalg.matrix_rank(augmented_matrix)

    y = int(rank_a != rank_augmented)
    lhs = f"rank([A])={rank_a}, rank([A|b])={rank_augmented}"
    rhs = f"y = {y}"
    print(
        f"{lhs}       =>      {rhs}"
    )
    return y


def codebreak(n):
    cipher_n_dir = f"{os.environ.get("DATA_DIRECTORY")}/cipher_{n}_dir"
    cipher_n__hdf5 = f"{cipher_n_dir}/cipher_{n}.hdf5"
    clauses_n__txt = f"{cipher_n_dir}/clauses_{n}.txt"
    beta_literals_sets_n__txt = f"{cipher_n_dir}/beta_literals_sets_{n}.txt"

    with h5py.File(cipher_n__hdf5, "r") as cipher_n__hdf5_file:
        with open(clauses_n__txt, "r") as clauses_n__txt_file:
            with open(beta_literals_sets_n__txt, "r") as beta_literals_sets_n__txt_file:
                y = recover_plaintext(
                    cipher_n__hdf5_file,
                    clauses_n__txt_file,
                    beta_literals_sets_n__txt_file,
                )
                return y


###

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Encrypt",
        description="Generates ciphertext file from plaintext based on Sebastian E. Schmittner's SAT-Based Public Key Encryption Scheme",
        epilog="https://eprint.iacr.org/2015/771.pdf",
    )

    parser.add_argument("n", type=int)
    args = parser.parse_args()

    print(codebreak(args.n))
