import math

### GENERATION PARAMETERS

PLAINTEXT = "r" # 0, 1, or "r" (random)
GENERATE_CLEARS_DATA = True

INCLUDE_CIPHERTEXT_N__TXT = True  # human-readable printout of ciphertext hdf5 file
INCLUDE_ENCRYPT_STDOUT_N__TXT = False

AUTOMATICALLY_TEST_CODEBREAK = True

### GENERATION OPTIMIZATIONS

LEAVE_CLAUSES_UNSORTED = False

### ENCRYPTION PARAMETERS

N = 100
M = 426
K = 3
ALPHA = 3
BETA = 10

# N: number of variables total.
# M: number of clauses total. [M > N]
# K: number of variables per clause.
# ALPHA: number of clauses per row. [4/5 are the upper bounds right now for reasonable solve time]
# BETA: number of rows.

### DECRYPTION PARAMETERS

### CODEBREAKING PARAMETERS

TERM_LENGTH_CUTOFF = math.floor(1.9 * ALPHA)

### NOT YET IMPLEMENTED PARAMETERS

# (a)
# To counter attacks discussed in Section 3.1.2, it is prefer-
# able if the clauses within one tuple share variables. This
# is particularly important if one of the clauses does not
# contain negations, i.e. s(i, 1) = . . . = s(i, k) = 0.
CONDITION_A = False

# (b)
# We have to ensure that each tuple shares at least one
# clause with another tuple to counter the attack dis-
# cussed in Section 3.2.
CONDITION_B = False

# (c)
# Each clause of pub is to appear in some tuple as dis
# cussed in Section 3.3.
CONDITION_C = False


CIPHERTEXT_SORTING_ORDER = [
    len,  # shortness of monomial
    # lambda term: list(term) # literals of monomial, ascending
]
REVERSE_CIPHERTEXT_SORTING = False
