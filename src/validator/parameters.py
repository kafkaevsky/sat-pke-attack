### Testing parameters
EVALUATE_CLEARS_DATA = True  # `evaluate n` clears all ciphertexts in ~/tests/
INCLUDE_READABLE_CIPHERTEXT = True  # Creates a readable ciphertext file.
LEAVE_CLAUSES_UNSORTED = False  # Optimization if clause order is unimportant.

### Encryption parameters
PLAINTEXT = "r"  # Plaintext. [0, 1, or "r" (random)]
N = 100  # Number of variables total.
M = 10  # Number of clauses total. [M > N]
K = 3  # Number of variables per clause.
BETA = 3  # Number of clauses per row.
ALPHA = 10  # Number of rows.

### Encryption invariants [Section 2.2]
CONDITIONS_B_C = True
CONDITION_A = True
# A) Clauses within one tuple ("beta groupings") share variables. [Discussed in Section 3.1.2]
# B) Tuples share at least one clause with another tuple. [Discussed in Section 3.2]
# C) Each clause of public key appears in some tuple. [Discussed in Section 3.3]
# Note that CONDITION_A is only defined by the paper for when CONDITIONS_B_C = True
# i.e. the constant CONDITION_A may be True only if CONDITIONS_B_C is True

### Attack parameters
import math
TERM_LENGTH_CUTOFF = math.floor(1.6 * BETA)  # 1.9? 1.6?
