1. Let S be a collection of subsets of the variables. Each subset s in S is formed by taking two clauses from the ciphertext and unioning the variables that they contain.
2. Let S' be S but where we duplicate each s in S a few times as follows. For each variable in s, for each clause from the public key that shares a variable with s, union the variables in that clause with s.
3. Let T be a collection of groups of clauses from the public key, i.e. a set of candidate beta groups. For each s in S', we take the set of all clauses that have all their variables contained within s to be a clause group and add this to T.

4. For each t_i = {c_1, ..., c_k} in T, do the following:
     i. Pick any monomial in ANF(negation of c_1). Let this monomial be m', which we represent as a set of variables. (It's also okay to pick the monomial "1" if present, in which case the set m' would be empty.)
     ii. Let S be the union of variables involved in c_2, ..., c_k, but excluding the variables already present in c_1.
     iii. Pick 100 uniformly random monomials m_1, ..., m_100 supported on S. As with m', represent these as sets of variables.
     iv. Count how many of the monomials m'm_1, ..., m'm_100 actually appear in the ciphertext. If the count is at least 30, add t_i to the new set T'. Otherwise, don't add t_i.

5. With the groups identified, we can simply set up a linear system with the unknowns being the coefficients of the random functions. Then we try to solve for the ciphertext under the assumption that the message bit was zero, and then again under the assumption that the message bit was one. If either case succeeds, this certifies what the encrypted bit was. Otherwise (which happens with inverse subexp probability) we just run the brute-force quasipoly-time linearization, which ensures that we always succeed and that the expected running time is polynomial.

That is,
When we set up the linear system assuming "message = 0", and then assuming "message = 1", there are four possibilities:
     1. Both systems have a solution. This is actually mathematically impossible.
     2. Only the "message = 0" case has a solution. Then this mathematically certifies that the correct message bit was 0.
     3. Only the "message = 1" case has a solution. As before, this certifies the message bit.
     4. Neither system has a solution. Then we go back to the T -> T' conversion, and re-run this with 1000 in place of 100 and 300 in place of 30.

