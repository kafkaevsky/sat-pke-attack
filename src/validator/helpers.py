import subprocess
import numpy as np
from itertools import chain as flatten, combinations as subset, product as cartesian

CONSTANT_MONOMIAL = tuple()  # empty tuple for constant 1

class Coefficient:
    def __init__(self, v):
        self.value = v

    def __repr__(self):
        return f"Coefficient(v={self.value})"

    def __eq__(self, other):
        if not isinstance(other, Coefficient):
            raise NotImplementedError
        return self.value == other.value


def run_zsh(cmd, capture=False):
    return subprocess.run(
        cmd,
        shell=True,
        text=True,
        executable="/bin/zsh",
        capture_output=capture,
    )


def distribute(iterable):
    return flatten.from_iterable(subset(iterable, r) for r in range(len(iterable) + 1))


def product_simplify(a: list, b: list):
    a = np.fromiter(a, dtype=tuple)
    b = np.fromiter(b, dtype=tuple)
    return [set(flatten(x, y)) for x in a for y in b]


# def cnf_to_neg_anf(term: list):
#     if not isinstance(term, list):
#         raise ValueError("`term` argument for cnf_to_neg_anf() must be a list")
#     term = term + [(1,)]
#     term = cartesian(*term)
#     term = filter(lambda t: 0 not in t and t.count(1) % 2 == 1, term)
#     term = map(lambda t: tuple(filter(lambda t: t != 1, t)), term)
#     term = map(lambda t: tuple(set(t)), term)
#     return list(term)

def cnf_to_neg_anf(clause: list):
    if not isinstance(clause, list):
        raise ValueError("`term` argument for cnf_to_neg_anf() must be a list")

    result = {frozenset()}

    for var, sign in clause:
        updated = {}
        for monomial in result:
            if sign != 0:
  
                for m_new in [monomial, monomial | frozenset([var])]:
                    if m_new in updated:
                        del updated[m_new]
                    else:
                        updated[m_new] = True
            else:
                m_new = monomial | frozenset([var])
                if m_new in updated:
                    del updated[m_new]
                else:
                    updated[m_new] = True
        result = set(updated.keys())

    return [tuple(sorted(m)) for m in result]


