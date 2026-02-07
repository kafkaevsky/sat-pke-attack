import argparse
import os
import sys
import h5py
import ast
import numpy as np
from collections import defaultdict
from itertools import combinations, product as cartesian
import galois
from ..parameters import *
from ..helpers import *
import random

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def _variables_sets(ciphertext_set, public_key_file, attempt_number):

    public_key_incl_sign = [tuple(c) for c in ast.literal_eval(public_key_file.read())]
    public_key = [(tuple(zip(*c))[0], c) for c in public_key_incl_sign]
    # ciphertext = {tuple(m) for m in ciphertext_file["ciphertext"]}
    ciphertext = ciphertext_set


    var_to_bit = {v: 1 << (v - 2) for v in range(2, N + 2)}
    bit_to_var = {b: v for v, b in var_to_bit.items()}

    unique_masks_set = set()

    for m in ciphertext:
        mask = 0
        for v in m:
            mask |= var_to_bit[v]
        unique_masks_set.add(mask)
    
    unique_masks_list = list(unique_masks_set)
    results = set()
    
    for i in range(len(unique_masks_list)):
        mask_a = unique_masks_list[i]
        for j in range(i, len(unique_masks_list)):
            mask_b = unique_masks_list[j]

            results.add(mask_a | mask_b)
            
    s = []
    for bitmapped_subset in results:
        current_vars = []
        for b, v in bit_to_var.items():
            if bitmapped_subset & b:
                current_vars.append(v)
        s.append(set(current_vars))



    print(0)

    clauses_sharing_variable__dict = {
        v: [(set(c[0]), c) for c in public_key if v in c[0]] for v in range(2, N + 2)
    }

    print(clauses_sharing_variable__dict)

    print(1)

    s_prime = (
        (
            s_i | set().union(*(c[0] for c in clauses_sharing_variable__dict[v]))
            for v in s_i
        )
        for s_i in s
    )

    print(2)

    clause_group_cache = {}

    def get_clause_group(s_prime_i_vars__set):

        cache_key = frozenset(s_prime_i_vars__set)
        if cache_key in clause_group_cache:
            return clause_group_cache[cache_key]

        beta_group = set()
        for v in s_prime_i_vars__set:
            for c in clauses_sharing_variable__dict[v]:
                if c[0] <= s_prime_i_vars__set:
                    beta_group.add(c[1])

        result = list(beta_group)
        clause_group_cache[cache_key] = result
        return result

    t = (get_clause_group(s_prime_i) for s_prime_i in flatten.from_iterable(s_prime))

    t_prime = []

    for i, t_i in enumerate(t):

        keep = False

        ######### 1

        c_1_incl_sign = t_i[0][1]
        neg_anf = cnf_to_neg_anf(list(c_1_incl_sign))
        m_star = set(random.choice(neg_anf))

        ######### 2

        c_1_vars = set(t_i[0][0])
        t_i_other_vars = set(flatten(*(c[0] for c in t_i[1:])))
        vars_excluding_c_1 = list(t_i_other_vars - c_1_vars)
        r = len(vars_excluding_c_1)

        ######### 3

        SAMPLE_COUNT = 10 ** (attempt_number + 1)
        HIT_THRESHOLD = 0.3 * SAMPLE_COUNT

        count = min(SAMPLE_COUNT, 2**r)
        sample_space = 2**r
        hits = 0

        seen_samples = set()
        samples_drawn = 0

        while samples_drawn < count:
            if r > 0:
                sample = random.randrange(sample_space)
                if sample in seen_samples:
                    continue

                seen_samples.add(sample)

                m_indices = [i for i in range(r) if (sample >> i) & 1]
                m_j = set(vars_excluding_c_1[i] for i in m_indices)
            else:
                m_j = set()

            samples_drawn += 1
            
            m_star_m_j = tuple(sorted(m_star | m_j))
            if m_star_m_j in ciphertext:
                hits += 1
            if hits >= HIT_THRESHOLD:
                keep = True
                break

        print(keep)
        if keep:
            t_prime.append(t_i)

    return t_prime


def _linearization(ciphertext_file, public_key_file):

    if "ciphertext" not in ciphertext_file:
        raise KeyError()

    ciphertext_set = {tuple(m) for m in ciphertext_file["ciphertext"]}


    attempt_number = 1
    t_prime = _variables_sets(ciphertext_set, public_key_file, attempt_number)
    print(len(t_prime))

    a_terms = defaultdict(list)
    coefficient_count = 0
    for i, t_prime_i in enumerate(t_prime):

        t_prime_i_incl_sign = [c[1] for c in t_prime_i]

        C = [cnf_to_neg_anf(list(c)) for c in t_prime_i_incl_sign]
        for i, C_i in enumerate(C):

            C_i = np.fromiter(list(C_i), dtype=object)
            C_minus_C_i = list(t_prime_i_incl_sign[:i]) + list(t_prime_i_incl_sign[i + 1 :])
            R_i_literals_set = list(set([l[0] for l in flatten(*C_minus_C_i)]))
            R_terms = np.fromiter(distribute(R_i_literals_set), dtype=object)
            n = len(R_terms)
            coefficient_count += n

            R_i_terms = R_terms
            R_i_coefficients = np.fromiter(
                map(
                    lambda i: Coefficient(i),
                    range(coefficient_count - n, coefficient_count),
                ),
                dtype=object,
            )
            R_i = np.fromiter(zip(R_i_coefficients, R_i_terms), dtype=object)

            #####
            unformatted_C_iR_i = np.fromiter(cartesian(R_i, C_i), dtype=object)
            
            C_iR_i = []

            for term in unformatted_C_iR_i:

                coefficient = term[0][0]
                literals = tuple(sorted([int(x) for x in set(term[0][1] + term[1])]))
                full_term = (coefficient, literals)
                C_iR_i.append(full_term)

            for term in C_iR_i:

                coefficient = term[0]
                literals = term[1]
                a_terms[literals] = a_terms[literals] + [coefficient]
            
        def clause_vector(coefficients, cols):
            v = np.zeros(cols)
            for c in coefficients:
                v[c.value] = int(not v[c.value])
            return v

    # ciphertext = set(map(lambda x: tuple([int(l) for l in x]), ciphertext))


    rows = len(a_terms.keys())
    cols = coefficient_count

    a = np.zeros((rows, cols), dtype=np.int64)
    b = np.zeros(rows, dtype=np.int64)

    for i, term in enumerate(a_terms):
        
        a[i] = clause_vector(a_terms[term], cols)
        b[i] = int(term in ciphertext_set)


    GF = galois.GF(2)
    a = GF(a)
    b = GF(b)

    rank_a = np.linalg.matrix_rank(a)
    augmented_matrix = np.hstack((a, b.reshape(-1, 1)))
    rank_augmented = np.linalg.matrix_rank(augmented_matrix)
    y = int(rank_a != rank_augmented)

    return y




def attack(args):

    CIPHERTEXT_DIRPATH = f"tests/c_{args.i}"
    CIPHERTEXT_FILEPATH = f"{CIPHERTEXT_DIRPATH}/ciphertext_{args.i}.hdf5"
    CLAUSES_FILEPATH = f"{CIPHERTEXT_DIRPATH}/public_key_{args.i}.txt"

    with h5py.File(CIPHERTEXT_FILEPATH, "r") as CIPHERTEXT_FILE:
        with open(CLAUSES_FILEPATH, "r") as CLAUSES_FILE:
            y = _linearization(CIPHERTEXT_FILE, CLAUSES_FILE)
            return y


def main():
    parser = argparse.ArgumentParser(prog="Attack")
    parser.add_argument("i", type=int)
    args = parser.parse_args()
    y = attack(args)
    print(y)


if __name__ == "__main__":
    main()
