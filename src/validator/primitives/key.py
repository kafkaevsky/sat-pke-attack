import secrets
import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
# from ..parameters import *


class KeyInstance:

    def __init__(self, n, m, k):
        self.n = n
        self.m = m
        self.k = k
        self.secure = secrets.SystemRandom()
        self.private_key_string = f"{bin(secrets.randbits(self.n))[2:]:0>{self.n}}"  # B^n

    def validate_clause(self, literal_index, parity):
        return int(self.private_key_string[literal_index]) == parity

    def _generate_valid_clause(self):
        clause_literals = [l+2 for l in self.secure.sample(range(self.n), self.k)]
        clause_signs = self.secure.sample([0, 1] * self.k, self.k)
        clause = [clause_literals, clause_signs]

        if any([self.validate_clause(int(clause[0][k]) - 2, clause[1][k]) for k in range(self.k)]):
            c = list(zip(*clause))
            return c
        return self._generate_valid_clause()

    def generate_clause_list(self):
        return [self._generate_valid_clause() for _ in range(self.m)]


# def get_key_instance(n, m, alpha, beta, k):
#     r