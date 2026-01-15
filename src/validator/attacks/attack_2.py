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
from functools import partial

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def _variables_sets(ciphertext_file, clauses_file):

    if "ciphertext" in ciphertext_file:

        #########
        ######### STEP 1
        #########

        ciphertext = [tuple(set(x)) for x in ciphertext_file["ciphertext"][:]]
        s = [set().union(*subset) for subset in combinations(ciphertext, 2)]

        #########
        ######### STEP 2
        #########

        def variable_contained(monomial, variable):
            return variable in monomial

        r = np.arange(2, N + 2)
        shared = dict(
            zip(
                r,
                [
                    set().union(
                        *filter(partial(variable_contained, variable=l), ciphertext)
                    )
                    for l in r
                ],
            )
        )

        s2 = set(
            flatten(
                *[
                    [
                        tuple(sorted(set().union(subset, shared.get(variable, set()))))
                        for variable in subset
                    ]
                    for subset in s
                ]
            )
        )

        clauses = np.array(ast.literal_eval(clauses_file.read()))
        clauses_variables_only = np.fromiter(
            map(lambda c: (c.T[0], c), clauses), dtype=object
        )

        #########
        ######### STEP 3
        #########

        def monomial_contained(monomial, subset):
            return set(monomial[0]).issubset(set(subset))

        t1 = [
            np.fromiter(filter(partial(monomial_contained, subset=s), clauses_variables_only), dtype=object)
            for s in s2
        ]

        # optimization: record vars:clauses in a dictionary for redundant cases

        #########
        ######### STEP 4
        #########

        t2 = []

        for collection in t1:

            abort = False

            for clause in collection:

                if abort:
                    break

                negative_anf = list(cnf_to_neg_anf(list(clause[1])))

                for monomial in negative_anf:

                    m_set = set(monomial)
                    excluding_set = set(clause[0]) - m_set

                    m1 = (monomial,)
                    R = list(distribute(excluding_set))

                    count = sum(
                        [
                            (tuple(sorted(m1m2)) in ciphertext)
                            for m1m2 in product_simplify(m1, R)
                        ]
                    )

                    if count / len(R) < 1/4:
                        abort = True
                        break

            collection_clauses = list(zip(*collection))[1]
            t2.append([list(x) for x in collection_clauses])
        return t2


def _linearization(ciphertext_file, clauses_file):

    clauses = _variables_sets(ciphertext_file, clauses_file)
    a_terms = defaultdict(list)
    coefficient_count = 0
    for clause in clauses:
        print("CLAUSE", clause)

        C = [cnf_to_neg_anf(c) for c in clause]
        for i, C_i in enumerate(C):

            C_i = np.fromiter(list(C_i), dtype=object)
            C_minus_C_i = list(clause[:i]) + list(clause[i + 1 :])
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

        ciphertext = ciphertext_file["ciphertext"][:]
        ciphertext = set(map(lambda x: tuple([int(l) for l in x]), ciphertext))



        # while encoding,
        # A) if y=0 and the ANF is (0 ⊕ ...):       the ciphertext is (0 ⊕ ...)
        # B) if y=0 and the ANF is (1 ⊕ ...):       the ciphertext is (1 ⊕ ...)
        # C) if y=1 and the ANF is (0 ⊕ ...):       the ciphertext is (0 ⊕ ...) ⊕ 1  =   (1 ⊕ ...)
        # D) if y=1 and the ANF is (1 ⊕ ...):       the ciphertext is (1 ⊕ ...) ⊕ 1  =   (0 ⊕ ...)

        ### Attack is only failing in case C (though case C does sometimes work)
        
        # missing_terms = ciphertext - set(a_terms.keys())    

        # if len(missing_terms) > 0:
        #     if missing_terms == {tuple()}:
        #         return 1
        #     return -3

        

        rows = len(a_terms.keys())
        cols = coefficient_count

        a = np.zeros((rows, cols), dtype=np.int64)
        b = np.zeros(rows, dtype=np.int64)

        for i, term in enumerate(a_terms):
            
            a[i] = clause_vector(a_terms[term], cols)
            b[i] = int(term in ciphertext)
            if sum(a[i]) == 0 and b[i] == 1:
                return -4

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
    CLAUSES_FILEPATH = f"{CIPHERTEXT_DIRPATH}/clauses_{args.i}.txt"

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
