import math

### GENERATION PARAMETERS

PLAINTEXT = 1
GENERATE_CLEARS_DATA = True

INCLUDE_BETA_LITERALS_SETS_N__TXT = True
INCLUDE_CIPHERTEXT_N__TXT = True  # human-readable printout of ciphertext hdf5 file
INCLUDE_ENCRYPT_STDOUT_N__TXT = False

### GENERATION OPTIMIZATIONS

LEAVE_CLAUSES_UNSORTED = False

### ENCRYPTION PARAMETERS

N = 100  # 4 # number of variables
M = 426  # 7 # number of clauses; M > N
K = 3  # number of variables per clause
ALPHA = 3  # 4 or 5 are the upper bound for reasonable solve times right now
BETA = 10

### DECRYPTION PARAMETERS


### CODEBREAKING PARAMETERS

TERM_LENGTH_CUTOFF = math.floor(1.9 * ALPHA)

### NOT YET IMPLEMENTED

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
