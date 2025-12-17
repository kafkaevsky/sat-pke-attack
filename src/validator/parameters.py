### testing
EVALUATE_CLEARS_DATA = True # Clears all ciphertexts in tests directory.
INCLUDE_READABLE_CIPHERTEXT = True  # Creates a readable ciphertext file.
LEAVE_CLAUSES_UNSORTED = False # Optimization if clause order is not important for readability.

### encryption
PLAINTEXT = "r" # Plaintext. [0, 1, or "r" (random)]
N = 100 # Number of variables total.
M = 426 # Number of clauses total. [M > N]
K = 3 # Number of variables per clause.
ALPHA = 3 # Number of clauses per row.
BETA = 10 # Number of rows.
CONDITION_A = False # Clauses within one tuple share variables. [Discussed in Section 3.1.2]
CONDITION_B = False # Tuples share at least one clause with another tuple. [Discussed in Section 3.2]
CONDITION_C = False # Each clause of public key appears in some tuple. [Discussed in Section 3.3]

### attack
import math
TERM_LENGTH_CUTOFF = math.floor(1.9 * ALPHA)